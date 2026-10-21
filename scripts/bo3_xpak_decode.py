#!/usr/bin/env python3
"""Inspect real BO3 T7 XPAK hash indices and bounded streamed payload commands.

All XPAK originals are temporary on GitHub runners. Only verified index
statistics, command counts and output checksums survive, never payloads.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download

BASE = "https://r2.houseofkublai.com"
PREFIX = "bo3/DUMP/zone/"
OBJECTS = {
    "base_patch_tu32.xpak": 1048576,
    "core_gfx.xpak": 786432,
    "core_common.xpak": 6291456,
    "core_frontend.xpak": 2883584,
    "core_frontend_patch.xpak": 4194304,
    "core_ui.xpak": 1048576,
    "core_pre_gfx.xpak": 786432,
    "en_initial.xpak": 13893632,
}
PRESETS = {
    "small": ("base_patch_tu32.xpak","core_gfx.xpak","core_common.xpak",
              "core_frontend.xpak","core_frontend_patch.xpak","core_ui.xpak",
              "core_pre_gfx.xpak","en_initial.xpak"),
    "extended": tuple(OBJECTS),
}
MAX_ENTRY_SOURCE = 2 * 1024 * 1024
MAX_ENTRY_DECODED = 4 * 1024 * 1024

def parse_index(path:Path)->tuple[dict,list]:
    with path.open("rb") as f:
        file_size=path.stat().st_size
        h=f.read(0x78)
        if len(h)<0x78 or h[:4]!=b"KAPI":
            raise ValueError("Not a T7 KAPI archive")
        ver=struct.unpack_from("<H",h,6)[0]
        if ver!=10:
            raise ValueError(f"Unknown BO3 KAPI version {ver}")
        declared_file_size=struct.unpack_from("<Q",h,0x10)[0]
        if declared_file_size!=file_size:
            raise ValueError("KAPI size does not match original source length")
        data_start,data_size,count,index_offset,index_size=struct.unpack_from("<QQQQQ",h,0x20)
        if count>500_000 or index_size != count*24:
            raise ValueError("KAPI hash table size/count mismatch")
        if data_start>file_size or data_size>file_size-data_start:
            raise ValueError("KAPI data region extends beyond source")
        if index_offset>file_size or index_size>file_size-index_offset:
            raise ValueError("KAPI hash index extends beyond source")
        f.seek(index_offset)
        table=f.read(index_size)
        if len(table)!=index_size:
            raise ValueError("Truncated KAPI hash table")
        entries=[]
        for i in range(count):
            key,relative_offset,raw_size=struct.unpack_from("<QQQ",table,i*24)
            size=raw_size & 0x00FFFFFFFFFFFFFF
            if relative_offset>data_size or size>data_size-relative_offset:
                raise ValueError(f"KAPI hash entry {i} exceeds data region")
            entries.append({"key":key,"relative_offset":relative_offset,
                            "packed_bytes":size,"size_flags":raw_size>>56})
        return {"declared_file_bytes":file_size,"version":ver,
                "data_start":data_start,"data_size":data_size,
                "hash_count":count,"hash_offset":index_offset,"hash_bytes":index_size},entries

def decompress_lz4_block(src:bytes,max_size:int=65536)->bytes:
    """Strict single-block LZ4 decoder to avoid adding native dependencies."""
    out=bytearray()
    pos=0
    while pos<len(src):
        token=src[pos];pos+=1
        lit=token>>4
        if lit==15:
            while True:
                if pos>=len(src):raise ValueError("Truncated LZ4 literal extension")
                n=src[pos];pos+=1;lit+=n
                if n!=255:break
        if pos+lit>len(src) or len(out)+lit>max_size:
            raise ValueError("LZ4 literal exceeds input/output")
        out.extend(src[pos:pos+lit]);pos+=lit
        if pos==len(src):break
        if pos+2>len(src):raise ValueError("Truncated LZ4 back reference")
        distance=src[pos]|(src[pos+1]<<8);pos+=2
        if distance==0 or distance>len(out):raise ValueError("Invalid LZ4 distance")
        match=(token & 0xF)+4
        if (token & 0xF)==15:
            while True:
                if pos>=len(src):raise ValueError("Truncated LZ4 match extension")
                n=src[pos];pos+=1;match+=n
                if n!=255:break
        if len(out)+match>max_size:raise ValueError("LZ4 match exceeds output bound")
        for _ in range(match):out.append(out[-distance])
    return bytes(out)

def probe_entry(f,meta,entry):
    physical=entry["packed_bytes"]
    if physical==0:
        return {"state":"zero_length"}
    if physical>MAX_ENTRY_SOURCE:
        return {"state":"source_size_limit","packed_bytes":physical}
    f.seek(meta["data_start"]+entry["relative_offset"])
    src=f.read(physical)
    if len(src)!=physical:raise ValueError("KAPI entry truncated")
    cursor=0
    output=bytearray()
    flags=Counter()
    headers=0
    while cursor < len(src):
        if cursor+128>len(src):
            return {"state":"partial_chunk_header","offset":cursor,
                    "flags":dict(flags),"decoded_bytes":len(output)}
        count,chunk_offset=struct.unpack_from("<II",src,cursor)
        if count==0 or count>30:
            return {"state":"unknown_chunk_header","offset":cursor,"count":count,
                    "flags":dict(flags),"decoded_bytes":len(output)}
        commands=struct.unpack_from("<30I",src,cursor+8)
        cursor+=128;headers+=1
        for word in commands[:count]:
            block_size=word&0xFFFFFF
            method=(word>>24)&0xFF
            flags[str(method)]+=1
            if cursor+block_size>len(src):
                raise ValueError("KAPI streamed block overruns hash record")
            block=src[cursor:cursor+block_size]
            if method==0:
                plain=block
            elif method==3:
                plain=decompress_lz4_block(block)
            else:
                return {"state":"codec_not_yet_supported","codec":method,"flags":dict(flags),
                        "decoded_bytes_before_codec":len(output)}
            if len(output)+len(plain)>MAX_ENTRY_DECODED:
                raise ValueError("KAPI streamed entry exceeds decoded byte budget")
            output.extend(plain)
            cursor+=block_size
        aligned=(cursor+0x7f)&~0x7f
        if aligned>len(src):
            if any(src[cursor:]):raise ValueError("Nonempty trailing KAPI padding")
            cursor=len(src)
        else:
            cursor=aligned
    return {"state":"decoded","chunk_headers":headers,
            "commands":dict(flags),"decoded_bytes":len(output),
            "decoded_sha256":hashlib.sha256(output).hexdigest()}

def main():
    mode=os.environ.get("BO3_XPAK_PRESET","small")
    if mode not in PRESETS:raise ValueError("Unknown T7 XPAK preset")
    reports=[]
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    with TemporaryDirectory(prefix="bo3-xpak-real-") as d:
        for name in PRESETS[mode]:
            if OBJECTS[name]>32*1024*1024:raise ValueError("Source object limit")
            key=PREFIX+name
            local=Path(d)/name
            got,digest,_=download(BASE+"/"+quote(key,safe="/"),local)
            if got!=OBJECTS[name]:raise ValueError(f"Original R2 length changed: {name}")
            meta,entries=parse_index(local)
            flags=Counter()
            status=Counter()
            first=[]
            with local.open("rb") as f:
                for i,entry in enumerate(entries):
                    r=probe_entry(f,meta,entry)
                    status[r["state"]]+=1
                    flags.update(r.get("commands",r.get("flags",{})))
                    if i<8:first.append({"hash_key":f"0x{entry['key']:016x}",
                                         "packed_bytes":entry["packed_bytes"],
                                         "state":r["state"],
                                         "decoded_bytes":r.get("decoded_bytes"),
                                         "decoded_sha256":r.get("decoded_sha256")})
            report={"key":key,"original_sha256":digest,**meta,
                    "source_hash_keys_unique":len({x["key"] for x in entries})==len(entries),
                    "entry_state_counts":dict(status),"command_counts":dict(flags),
                    "entry_size_flags":dict(Counter(x["size_flags"] for x in entries)),
                    "first_eight_entries":first}
            reports.append(report)
            print(json.dumps(report,sort_keys=True),flush=True)
    (root/"bo3_t7_xpak_index.json").write_text(json.dumps(reports,indent=2)+"\n",encoding="utf-8")
    print(f"Indexed {len(reports)} original BO3 KAPI source archives",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 XPAK validation failure: {e}",file=sys.stderr)
        sys.exit(1)
