#!/usr/bin/env python3
"""Decode a REAL CS2 retail Vulkan shader frame with its original 64-KiB
Valve Zstd dictionary. This is a source-GPU smoke test, not a claim that
the first physically stored permutation is selected by any particular VMAT.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
import zstandard as zstd
from cs2_material_source_handoff import parse_vpk_index, VPK_DIRECTORY_ARCHIVE

STAGE = "shaders/vfx/csgo_vertexlitgeneric_vulkan_50_vs.vcs"
DICT_NAME = "vfx_zstd_255df362.bin"
DICT_MAGIC = 0xEC30A437
DICT_ID = 0x255DF362

def original_vcs(index_path, depot_root):
    index = parse_vpk_index(index_path)
    entry = index.entries.get(STAGE)
    if entry is None:
        raise ValueError(f"requested source stage not indexed: {STAGE}")
    if entry.archive_index == VPK_DIRECTORY_ARCHIVE:
        path, offset = index_path, index.data_start + entry.offset
    else:
        path = depot_root / f"game/csgo/shaders_vulkan_{entry.archive_index:03d}.vpk"
        offset = entry.offset
    with path.open("rb") as stream:
        stream.seek(offset)
        body = stream.read(entry.length)
    if len(body) != entry.length:
        raise ValueError("truncated original VCS source bytes")
    original = entry.preload + body
    crc = zlib.crc32(original) & 0xFFFFFFFF
    if crc != entry.crc32:
        raise ValueError(f"original VPK stage CRC mismatch {crc:08x} != {entry.crc32:08x}")
    return original, {
        "vcs_path": STAGE,
        "original_vcs_crc32": f"{entry.crc32:08x}",
        "original_vcs_sha256": hashlib.sha256(original).hexdigest(),
        "original_vcs_bytes": len(original),
        "original_vpk_segment": entry.archive_index
    }

def original_dictionary(path):
    data = path.read_bytes()
    if len(data) != 65536:
        raise ValueError("original Valve VCS shader dictionary not 65,536 bytes")
    magic, identity = struct.unpack_from("<II",data)
    if (magic,identity) != (DICT_MAGIC,DICT_ID):
        raise ValueError(f"incorrect original Valve dictionary magic/id {magic:x}/{identity:x}")
    return data

def first_native_spirv(stage, dictionary):
    if len(stage)<44:
        raise ValueError("truncated VCS source")
    metadata_size = struct.unpack_from("<I",stage)[0]
    header,resource_version = struct.unpack_from("<HH",stage,4)
    if header != 12 or resource_version != 72:
        raise ValueError("original VCS compiler metadata does not use Source2 v72")
    if not 32<=metadata_size<=len(stage)-12:
        raise ValueError("original VCS compiler metadata extent is invalid")
    frame_kind,expected,encoded = struct.unpack_from("<iII",stage,metadata_size)
    if frame_kind != -5:
        raise ValueError(f"expected original Vulkan dictionary kind -5, got {frame_kind}")
    if expected == 0 or expected>64*1024*1024:
        raise ValueError("decoded original GPU frame exceeds bounded source extent")
    start = metadata_size + 12
    end = start + encoded
    if encoded == 0 or end>len(stage):
        raise ValueError("original GPU frame extends past Source 2 VCS")
    dctx = zstd.ZstdDecompressor(dict_data=zstd.ZstdCompressionDict(dictionary))
    frame = dctx.decompress(stage[start:end],max_output_size=expected)
    if len(frame)!=expected:
        raise ValueError("original Valve compressed shader frame extent mismatch")
    wrapper, length = struct.unpack_from("<II",frame)
    if not (2<=wrapper<=6) or length<20 or length%4 or 8+length>len(frame):
        raise ValueError("original GPU shader slice has invalid wrapper/extent")
    spirv = frame[8:8+length]
    if struct.unpack_from("<I",spirv)[0]!=0x07230203:
        raise ValueError("selected first original native shader is not SPIR-V")
    at=20
    instructions=0
    while at<len(spirv):
        count=struct.unpack_from("<I",spirv,at)[0]>>16
        if count==0 or at+4*count>len(spirv):
            raise ValueError("original compiled SPIR-V instruction escapes bounds")
        at+=4*count
        instructions+=1
    return spirv,{
        "first_physical_frame_offset":metadata_size,
        "frame_compression_type":frame_kind,
        "frame_compressed_bytes":encoded,
        "frame_expanded_bytes":expected,
        "spirv_wrapper_version":wrapper,
        "spirv_original_bytes":len(spirv),
        "spirv_original_sha256":hashlib.sha256(spirv).hexdigest(),
        "spirv_instruction_count":instructions,
        "runtime_permutation_selection":"NOT ESTABLISHED"
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--vpk-index",type=Path)
    parser.add_argument("--depot-root",type=Path)
    parser.add_argument("--dictionary",type=Path)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    try:
        if args.self_test:
            assert len(STAGE)>20 and DICT_ID==0x255DF362
            print("Authentic Source 2 shader smoke constraints passed")
            return 0
        if not all([args.vpk_index,args.depot_root,args.dictionary,args.output]):
            raise ValueError("missing source VPK/dictionary/output argument")
        vcs,meta=original_vcs(args.vpk_index,args.depot_root)
        dictionary=original_dictionary(args.dictionary)
        spirv,smoke=first_native_spirv(vcs,dictionary)
        output=args.output
        (output/"cs2-base-resources/shaders/vfx").mkdir(parents=True,exist_ok=True)
        (output/"cs2-base-resources"/STAGE).write_bytes(vcs)
        (output/"cs2-base-resources/shaders"/DICT_NAME).write_bytes(dictionary)
        (output/"first-source-physical-vs.spv").write_bytes(spirv)
        manifest={
            **meta,**smoke,
            "original_dictionary":"ValveResourceFormat recovered original Valve dictionary 0x255df362",
            "original_dictionary_sha256":hashlib.sha256(dictionary).hexdigest(),
            "selection_note":"first physical source frame only; no inferred VMAT static/dynamic runtime ID"
        }
        (output/"original_native_shader_smoke.json").write_text(
            json.dumps(manifest,indent=2)+"\n",encoding="utf-8"
        )
        print(json.dumps(manifest,indent=2))
        return 0
    except Exception as exc:
        print(f"original CS2 native SPIR-V source smoke failed: {exc}")
        return 1

if __name__=="__main__":
    raise SystemExit(main())
