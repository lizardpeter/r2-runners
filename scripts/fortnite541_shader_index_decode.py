#!/usr/bin/env python3
"""Decode every original UE4.21 shader record from verified retail archives.

Keeps complete source .ushaderbytecode files as the main artifact. This is an
exhaustive Zlib+DXBC structural decode, NOT yet a translation to executable
universal Vulkan/WGSL surface programs. Records retain original UE4 pre-DXBC
parameter-map bytes (never discarded). The index's SHA-1 provenance comes
from the authenticated PAK entry handoff performed before this script.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import zlib

RECORD_BYTES=37
STAGES=("Vertex","Hull","Domain","Pixel","Geometry","Compute")

def check_dxbc(payload:bytes)->tuple[int,int,Counter]:
    start=payload.find(b"DXBC")
    if start<0 or len(payload)-start<32:
        raise ValueError("authored shader lacks an actual DXBC container")
    extent,chunks=struct.unpack_from("<II",payload,start+24)
    if not (32<=extent<=len(payload)-start and 0<chunks<=256 and 32+chunks*4<=extent):
        raise ValueError("DXBC container original size/table invalid")
    fourcc=Counter()
    for i in range(chunks):
        offset=struct.unpack_from("<I",payload,start+32+4*i)[0]
        if offset+8>extent:
            raise ValueError("DXBC source chunk offset outside container")
        count=struct.unpack_from("<I",payload,start+offset+4)[0]
        if offset+8+count>extent:
            raise ValueError("DXBC source chunk payload outside container")
        fourcc[payload[start+offset:start+offset+4].decode("ascii","replace")]+=1
    return start,extent,fourcc

def decode_file(path:Path)->dict:
    total=path.stat().st_size
    errors=[]
    frequency=Counter()
    chunks=Counter()
    count=0
    expanded_bytes=0
    prelude_bytes=0
    digest=hashlib.sha1()
    with path.open("rb") as source:
        # The original archive itself has been source-authenticated; retain
        # a new complete-source SHA1 as a separate independently verified value.
        for part in iter(lambda:source.read(1024*1024),b""):
            digest.update(part)
        source.seek(0)
        first=source.read(8)
        if len(first)!=8:
            raise ValueError("truncated original UE4 shader library")
        version,number=struct.unpack("<II",first)
        if version!=1 or not 0<number<=200_000:
            raise ValueError(f"unrecognized original UE4 shader archive version/count: {version}/{number}")
        code_start=8+number*RECORD_BYTES
        if code_start>=total:
            raise ValueError("source shader record table escapes archive")
        records=source.read(number*RECORD_BYTES)
        if len(records)!=number*RECORD_BYTES:
            raise ValueError("original shader hash/offset table truncated")
        code_bytes=0
        seen=set()
        for i in range(number):
            data=records[i*RECORD_BYTES:(i+1)*RECORD_BYTES]
            original_hash,offset,stored,expanded,stage=struct.unpack("<20sQIIB",data)
            if (original_hash in seen or offset!=code_bytes or
                stored==0 or expanded==0 or stored>2*1024*1024 or
                expanded>4*1024*1024 or stage>=len(STAGES)):
                raise ValueError(f"invalid original shader offset, hash, source code lengths or stage #{i}")
            seen.add(original_hash)
            code_bytes+=stored
            if code_start+code_bytes>total:
                raise ValueError(f"original shader #{i} exceeds exact archive bytes")
            raw=source.read(stored)
            if len(raw)!=stored:
                raise ValueError(f"original compressed shader #{i} truncated")
            try:
                decoded=zlib.decompress(raw)
            except zlib.error as exc:
                raise ValueError(f"original shader #{i} zlib decode failure: {exc}") from exc
            if len(decoded)!=expanded:
                raise ValueError(f"original shader #{i} uncompacted length mismatch")
            prefix,container_size,shader_chunks=check_dxbc(decoded)
            chunks.update(shader_chunks)
            prelude_bytes+=prefix
            expanded_bytes+=expanded
            frequency[STAGES[stage]]+=1
            count+=1
        if source.tell()!=total:
            raise ValueError("original UE4 indexed shader bytes do not fully cover source")
    return {
        "source_path":str(path),
        "source_bytes":total,
        "authenticated_payload_sha1_recomputed":digest.hexdigest(),
        "shader_code_library_format":1,
        "decoded_original_shaders":count,
        "shader_stage_counts":dict(frequency),
        "original_expanded_shader_bytes":expanded_bytes,
        "original_unreal_parameter_prefix_bytes":prelude_bytes,
        "original_dxbc_chunk_counts":dict(chunks),
        "untranslated_semantics":"Unreal shader parameter resource ABI, executable SSA/WGSL translation, and original material selection still require universal IR admission",
        "source_binary_retained":True,
    }

def run(root:Path,report:Path):
    archives=sorted(root.rglob("*.ushaderbytecode"))
    results=[]
    for archive in archives:
        result=decode_file(archive)
        result["source_path"]=archive.relative_to(root).as_posix()
        print("FORTNITE541_RETAIL_SHADER_LIBRARY_DECODED",
              result["source_path"],"originals",result["decoded_original_shaders"],
              "stage",result["shader_stage_counts"],"sha1",
              result["authenticated_payload_sha1_recomputed"],flush=True)
        results.append(result)
    report.mkdir(parents=True,exist_ok=True)
    (report/"original-ue4-shader-decode.json").write_text(
        json.dumps({"archives":results,"original_source_files_preserved":True},indent=2)+"\n")
    print("FORTNITE541_REAL_SHADER_DECODE_CENSUS",
          "original_archives",len(results),"all_valid_decompressed_shaders",
          sum(x["decoded_original_shaders"] for x in results),flush=True)

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    run(args.root,args.report)
