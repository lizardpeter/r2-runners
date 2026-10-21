"""Generic H1 XAssetList evidence analyzer; never assumes a map-specific type schema.

Operates on the original decoded-stream prefix, retained only in memory of authenticated, decompressed XFile
bytes. Reports counts, candidate record layouts and short bounded samples.
"""
from collections import Counter
import struct

XFILE_BYTES = 72
DIRECTORY_BYTES = 32
MARKER = 0xFDFDFDFFFFFFFFFF


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def likely_pointer(v: int) -> bool:
    # Candidate source tags, not yet an interpreted relocation schema.
    return v == 0 or v == MARKER or ((v >> 48) == 0xFDFD)


def scan_table_candidates(data: bytes, count: int, limit: int = 12) -> list[dict]:
    """Find contiguous 16-byte {u32 type, u32 padding, u64 pointer} runs.

    Scanning is hypothesis generation only. We do not count any hit as a real
    asset directory until loader pointer and type constraints verify it.
    """
    candidates = []
    if not (1 <= count <= 1_000_000):
        return candidates
    stop = len(data) - 16 * 32
    if stop < DIRECTORY_BYTES:
        return candidates

    def evaluate(at: int):
        size = min(96, count)
        types = Counter()
        markers = 0
        filled = 0
        for i in range(size):
            k = at + 16 * i
            kind, pad, ptr = struct.unpack_from("<IIQ", data, k)
            if not (0 <= kind <= 255 and pad == 0 and likely_pointer(ptr)):
                break
            types[kind] += 1
            if ptr != 0:
                markers += 1
            if kind != 0:
                filled += 1
        else:
            pass
        observed = sum(types.values())
        min_records = min(count, 24)
        if observed >= min_records and markers >= (observed+1)//2 and filled >= max(1,observed//5):
            return {"offset": at, "first_records": observed, "tagged_ptr_count": markers,
                    "nonzero_types": filled, "type_histogram":dict(types.most_common(12))}
        return None

    # Scan alignment first. Fixed-size 16B entries normally retain 8-byte
    # alignment; test both mod-16 classes through an 8-byte step.
    for at in range(112, stop, 8):
        v = evaluate(at)
        if v:
            candidates.append(v)
    candidates.sort(key=lambda x:(-x["first_records"],-x["tagged_ptr_count"],x["offset"]))
    return candidates[:limit]




def analyze_script_string_run(data: bytes, script_count: int) -> dict:
    """Inspect candidate inline NUL-terminated strings after the pointer vector.

    The 40-byte root includes a globals pointer. Do not assume these
    guesses are authenticated script-string index mappings until count and
    the continuation boundary have been proven across more zones.
    """
    if not 0 < script_count <= 100_000:
        return {}
    vector_end = 112 + script_count * 8
    if vector_end + 8 >= len(data):
        return {"status":"pointer_vector_outside_prefix"}
    expected = u64(data,vector_end)
    runs=[]
    for start in (vector_end,vector_end+8):
        segment=data[start:min(len(data),start+128*1024)]
        end=0
        for b in segment:
            if b not in (0,9,10,13) and not 32<=b<=126:
                break
            end+=1
        raw=segment[:end]
        strings=[x.decode("ascii","replace") for x in raw.split(b"\0") if x]
        runs.append({
            "start_offset":start,
            "printable_run_bytes":end,
            "nul_count":raw.count(0),
            "candidate_strings":len(strings),
            "first_candidate_strings":[x[:72] for x in strings[:12]],
            "stopped_offset":start+end,
            "string_count_matches_inline_marker_count":len(strings)==script_count-1,
        })
    return {"next_word_after_pointer_vector":f"{expected:016x}",
            "candidate_string_runs":runs}



def decode_source_script_slots(data: bytes, count: int) -> dict:
    """Recover H1 XAssetList's authored script indices from inline strings.

    After the complete pointer array, N inline NUL-terminated strings follow
    in slot order. Preserve empty
    strings distinctly from null slots.
    """
    if not 0 <= count <= 100000:
        raise ValueError("invalid H1 script count")
    if count == 0:
        return {"status":"no_script_strings","slots":0}
    pointer_end=112+count*8
    if len(data)<pointer_end:
        raise ValueError("truncated H1 script string pointer vector")
    pointers=[u64(data,112+i*8) for i in range(count)]
    cursor=pointer_end
    names=[]
    for i,pointer in enumerate(pointers):
        if pointer==0:
            names.append(None)
            continue
        if pointer!=MARKER:
            raise ValueError(f"unrecognized H1 script pointer tag at index {i}: {pointer:#x}")
        terminator=data.find(b"\0",cursor)
        if terminator<0:
            raise ValueError(f"unterminated H1 inline script string at index {i}")
        if terminator-cursor>4096:
            raise ValueError(f"unreasonable inline script string length at index {i}")
        value=data[cursor:terminator].decode("utf-8")
        names.append(value)
        cursor=terminator+1
    import hashlib
    # Encoded name+index boundary is retained, so null versus empty remain
    # distinguishable under the digest.
    serialized=b"".join(struct.pack("<I",i)+(b"\xff" if name is None
                else name.encode("utf-8")+b"\0") for i,name in enumerate(names))
    return {
        "status":"full_script_string_table_recovered",
        "slots":len(names),
        "inline_strings":sum(v is not None for v in names),
        "null_slots":sum(v is None for v in names),
        "empty_inline_strings":sum(v=="" for v in names if v is not None),
        "inline_blob_end_offset":cursor,
        "indexed_names_sha256":hashlib.sha256(serialized).hexdigest(),
        "first_indexed_names":[{"index":i,"name":v} for i,v in list(enumerate(names))[:15]],
    }



def probe_xasset_array_after_strings(data: bytes, asset_count: int, script_end: int) -> list[dict]:
    """Evidence only: H1 XAsset is a 16-byte (u32 type, pad, u64 header) pair.

    The game may serialize XGlobals data before this array, so a failed
    nearby search is not proof that the array is absent. Record bounded,
    source-backed candidates and never invent asset entries.
    """
    if not 2 <= asset_count <= 1000000:
        return []
    base=(script_end+7)&~7
    out=[]
    for start in range(max(112,base),min(len(data)-32,base+1024),8):
        types=Counter()
        tags=Counter()
        invalid=None
        examined=min(128,asset_count)
        for i in range(examined):
            offset=start+i*16
            if offset+16>len(data):
                invalid="truncated"
                break
            kind,pad,pointer=struct.unpack_from("<IIQ",data,offset)
            if kind>96 or pad!=0:
                invalid=f"invalid type/padding after {i} records"
                break
            types[kind]+=1
            tags["inline" if pointer==MARKER else "null" if pointer==0 else
                 "other_tag" if likely_pointer(pointer) else "unknown"]+=1
        accepted=sum(types.values())
        if accepted>=min(2,asset_count) and sum(v for k,v in types.items() if k!=0)>0:
            out.append({
                "offset":start,
                "valid_consecutive_records":accepted,
                "examined_records":examined,
                "type_histogram":dict(types.most_common(12)),
                "pointer_tags":dict(tags),
                "stopped_reason":invalid,
            })
    out.sort(key=lambda r:(-r["valid_consecutive_records"],
                           -r["pointer_tags"].get("inline",0),r["offset"]))
    return out[:8]

def inspect_prefix(data: bytes) -> dict:
    if len(data) < 104:
        raise ValueError("No complete H1 XAssetList prelude")
    script_count, script_ptr, asset_count, asset_ptr, globals_ptr = struct.unpack_from("<QQQQQ", data, 72)
    result = {
        "sampled_decompressed_prefix_bytes":len(data),
        "xasset_list_decompressed_offset":72,
        "script_string_count":script_count,
        "script_string_pointer_raw_hex":f"{script_ptr:016x}",
        "asset_count":asset_count,
        "asset_array_pointer_raw_hex":f"{asset_ptr:016x}",
        "globals_pointer_raw_hex":f"{globals_ptr:016x}",
    }
    # Distinguish the pointer-vector hypothesis from actual string relocation.
    if script_count < 100000 and 112 + script_count * 8 <= len(data):
        ptrs=[u64(data, 112+i*8) for i in range(script_count)]
        hist=Counter("marker" if p==MARKER else "null" if p==0 else
                     "tagged" if (p>>48)==0xFDFD else "other" for p in ptrs)
        result["script_pointer_vector_at_112"]=dict(hist)
        result["inline_script_string_run_analysis"]=analyze_script_string_run(data,script_count)
        result["decoded_indexed_script_strings"]=decode_source_script_slots(data,script_count)
        result["sample_words_following_pointer_vector"]=[
            f"{u64(data,p):016x}" for p in range(112+script_count*8,
                                                  min(len(data)-8,112+script_count*8+64),8)]
    result["sample_8byte_words_at_112"]=[f"{u64(data,p):016x}" for p in range(112, min(len(data)-8,360),8)]
    end_of_strings=(result.get("decoded_indexed_script_strings") or {}).get("inline_blob_end_offset",112)
    result["xasset_16byte_table_candidate_runs"]=scan_table_candidates(data, asset_count)
    result["xasset_array_candidates_near_root"]=probe_xasset_array_after_strings(
        data,asset_count,end_of_strings)
    return result
