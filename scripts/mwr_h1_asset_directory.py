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
    for at in range(104, stop, 8):
        v = evaluate(at)
        if v:
            candidates.append(v)
    candidates.sort(key=lambda x:(-x["first_records"],-x["tagged_ptr_count"],x["offset"]))
    return candidates[:limit]


def inspect_prefix(data: bytes) -> dict:
    if len(data) < 104:
        raise ValueError("No complete H1 XAssetList prelude")
    script_count, script_ptr, asset_count, asset_ptr = struct.unpack_from("<QQQQ", data, 72)
    result = {
        "sampled_decompressed_prefix_bytes":len(data),
        "xasset_list_decompressed_offset":72,
        "script_string_count":script_count,
        "script_string_pointer_raw_hex":f"{script_ptr:016x}",
        "asset_count":asset_count,
        "asset_array_pointer_raw_hex":f"{asset_ptr:016x}",
    }
    # Distinguish the pointer-vector hypothesis from actual string relocation.
    if script_count < 100000 and 104 + script_count * 8 <= len(data):
        ptrs=[u64(data, 104+i*8) for i in range(script_count)]
        hist=Counter("marker" if p==MARKER else "null" if p==0 else
                     "tagged" if (p>>48)==0xFDFD else "other" for p in ptrs)
        result["script_pointer_vector_at_104_hypothesis"]=dict(hist)
        result["sample_words_following_pointer_vector"]=[
            f"{u64(data,p):016x}" for p in range(104+script_count*8,
                                                  min(len(data)-8,104+script_count*8+64),8)]
    result["sample_8byte_words_at_104"]=[f"{u64(data,p):016x}" for p in range(104, min(len(data)-8,360),8)]
    result["xasset_16byte_table_candidate_runs"]=scan_table_candidates(data, asset_count)
    return result
