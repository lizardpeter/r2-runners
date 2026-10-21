"""Generic H1 XAssetList evidence analyzer; never assumes a map-specific type schema.

Operates on the original decoded-stream prefix, retained only in memory of authenticated, decompressed XFile
bytes. Reports counts, candidate record layouts and short bounded samples.
"""
from collections import Counter
from mwr_h1_asset_payload import analyze_first_source_body, inspect_sequential_source_files
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
    if count < 32:
        return candidates
    stop = len(data) - 16 * min(96, count)
    if stop < 104:
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



def inspect_post_script_cursor(data: bytes, script_end: int, asset_count: int) -> dict:
    aligned=(script_end+7)&~7
    max_bytes=min(384,len(data)-aligned)
    if max_bytes < 40:
        return {"status":"not_available"}
    blob=data[aligned:aligned+max_bytes]
    words=[struct.unpack_from("<Q",blob,i)[0] for i in range(0,len(blob)-7,8)]
    dwords=[struct.unpack_from("<I",blob,i)[0] for i in range(0,len(blob)-3,4)]
    return {
        "after_script_unaligned":script_end,
        "after_script_aligned":aligned,
        "first_192_raw_hex":blob[:192].hex(" "),
        "first_36_u64":[f"{v:016x}" for v in words[:36]],
        "first_48_u32":dwords[:48],
        "asset_count_from_root":asset_count,
    }



def inspect_h1_gfx_globals(data: bytes, script_end: int, count: int) -> dict:
    """Parse XGlobals+XGfxGlobals with source-native field widths.

    The actual byte cursor is the end of inline strings: the original
    archive does NOT insert a blanket align-to-eight boundary here.
    H1 runtime structures identify ten count/pointer-bearing arrays.
    """
    at=script_end
    if at+112>len(data):return {"status":"not_present_in_prefix"}
    gfx_ptr=u64(data,at)
    if gfx_ptr==0:return {"status":"no_gfx_globals","source_cursor":at}
    if gfx_ptr!=MARKER:return {"status":"unsupported_gfx_pointer_tag","tag":f"{gfx_ptr:016x}"}
    b=at+8
    depth,blend=struct.unpack_from("<II",data,b)
    ptrs=[u64(data,b+i) for i in (8,16,24,32,56,64,72,80,88,96)]
    prim,obj,stable=struct.unpack_from("<III",data,b+40)
    sizes=[(depth,8),(blend,12),(depth,8),(blend,8),(prim,4),(obj,4),(stable,4),
           (prim,8),(obj,8),(stable,8)]
    start=b+104
    expected=sum(n*size for n,size in sizes)
    return {
        "status":"header_parsed",
        "xglobals_pointer_offset":at,
        "xgfxglobals_struct_offset":b,
        "xgfxglobals_struct_end":start,
        "depth_stencil_count":depth,"blend_count":blend,
        "per_primitive_cb_count":prim,"per_object_cb_count":obj,
        "stable_cb_count":stable,
        "array_pointer_tags":[f"{p:016x}" for p in ptrs],
        "all_array_pointers_are_inline":all(p==MARKER for p in ptrs),
        "array_lengths_source_struct":sizes,
        "candidate_arrays_total_bytes":expected,
        "candidate_after_arrays":start+expected,
        "after_arrays_first_192_hex":data[start+expected:start+expected+192].hex(" "),
        "after_arrays_first_20_u64":[f"{u64(data,o):016x}" for o in range(start+expected,
                            min(start+expected+8*20,len(data)-7),8)],
        "candidate_asset_array_near_after_globals":probe_xasset_array_wide(
            data, count, start+expected, 4096)
    }


def probe_xasset_array_wide(data: bytes, count: int, expected: int, radius: int) -> list[dict]:
    """Search all byte alignments around source-computed global-array end."""
    if count<2 or expected>len(data):return []
    out=[]
    start=max(112,expected-radius)
    stop=min(len(data)-16*min(count,32),expected+radius)
    for at in range(start,stop):
        types=Counter()
        tags=Counter()
        for i in range(min(80,count)):
            offset=at+16*i
            kind,pad,ptr=struct.unpack_from("<IIQ",data,offset)
            if kind>=71 or pad or ptr not in (0,MARKER):break
            types[kind]+=1
            tags["inline" if ptr==MARKER else "null"]+=1
        n=sum(types.values())
        if n>=min(count,16) and sum(v for k,v in types.items() if k!=0)>=max(1,n//8):
            out.append({
                "offset":at,"delta_from_predicted":at-expected,
                "matched":n,"types":dict(types.most_common(16)),"pointer_tags":dict(tags)
            })
    out.sort(key=lambda d:(-d["matched"],abs(d["delta_from_predicted"])))
    return out[:8]



def verify_full_xasset_arrays(data: bytes, directory: dict, gfx: dict) -> dict:
    """Verify EVERY authored record before promoting a candidate to real table.

    No game/map-specific offsets. The only search region is bounded by the
    already decoded XGlobals structure and its original serialized arrays.
    A valid result must pass the entire declared asset count and source
    pointer checks, not a short heuristic prefix.
    """
    count=directory["asset_count"]
    if not 1<=count<=100_000:
        return {"status":"not_applicable"}
    if gfx.get("status")=="header_parsed":
        start=gfx["xgfxglobals_struct_end"]
        expected=gfx["candidate_after_arrays"]
    elif gfx.get("status")=="no_gfx_globals":
        start=gfx["source_cursor"]+8
        expected=start
    else:
        return {"status":"unsupported_globals_layout","gfx_status":gfx.get("status")}
    limit=min(len(data)-16*count,start+max(4096,2*(expected-start)+4096))
    if limit<start:
        return {"status":"insufficient_prefix","required":start+16*count,"have":len(data)}
    marker=struct.pack("<Q",MARKER)
    passes=[]
    rejected=Counter()
    at=start
    while at<=limit:
        # Fast reject all 16-byte starts whose first pair is not a valid
        # H1 source type + pointer. The full table validation is bounded.
        kind,pad,ptr=struct.unpack_from("<IIQ",data,at)
        if not (kind<71 and pad==0 and ptr in (0,MARKER)):
            at+=1
            continue
        # To avoid empty/garbage regions require at least one non-zero
        # source type, then check source pointer validity across all slots.
        counts=Counter()
        tags=Counter()
        for i in range(count):
            where=at+i*16
            k,p,reference=struct.unpack_from("<IIQ",data,where)
            if k>=71 or p!=0 or reference not in (0,MARKER):
                rejected["bad_record"]+=1
                break
            counts[k]+=1
            tags["inline" if reference==MARKER else "null"]+=1
        else:
            if any(k!=0 and v>0 for k,v in counts.items()):
                passes.append({
                    "start_offset":at,
                    "end_offset":at+count*16,
                    "verified_records":count,
                    "delta_from_model":at-expected,
                    "type_histogram":dict(sorted(counts.items())),
                    "source_pointer_tags":dict(tags),
                    "source_type_indices_in_order_sha256":__import__("hashlib").sha256(
                        data[at:at+count*16]).hexdigest(),
                    "first_16_asset_types":[struct.unpack_from("<I",data,at+i*16)[0]
                                            for i in range(min(count,16))],
                    "first_asset_body_160_hex":data[at+count*16:at+count*16+160].hex(" "),
                    "first_asset_body_words":[f"{u64(data,pos):016x}" for pos in
                        range(at+count*16,min(at+count*16+8*16,len(data)-7),8)]
                })
        at+=1
    return {"status":"fully_verified" if len(passes)==1 else
            "ambiguous" if passes else "unresolved",
            "candidate_count":len(passes),
            "validated_tables":passes[:8],
            "search_start":start,"search_end":limit,"expected_source_cursor":expected,
            "partial_match_rejections":dict(rejected)}


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
    result["candidate_post_script_globals"]=inspect_post_script_cursor(data,end_of_strings,asset_count)
    result["parsed_source_gfx_globals"]=inspect_h1_gfx_globals(data,end_of_strings,asset_count)
    result["complete_xasset_directory_evidence"]=verify_full_xasset_arrays(
        data,result,result["parsed_source_gfx_globals"])
    verified=result["complete_xasset_directory_evidence"].get("validated_tables",[])
    if result["complete_xasset_directory_evidence"].get("status")=="fully_verified" and verified:
        result["first_original_asset_payload"]=analyze_first_source_body(data,verified[0])
        result["sequential_original_source_files"]=inspect_sequential_source_files(data,verified[0])
    result["xasset_array_candidates_near_root"]=probe_xasset_array_after_strings(
        data,asset_count,end_of_strings)
    return result
