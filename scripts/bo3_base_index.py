#!/usr/bin/env python3
"""Inspect complete authentic T7 base.xpak hash index using exact R2 byte ranges.

The original object is >15 GB; ranged reads retrieve its complete 0x78-byte
header and exact 24-byte hash records into runner-local memory. No game data
or source index bytes are committed or published. Later range readers can
fetch the exact indexed packed payloads without arbitrary upload size limits.
"""
from __future__ import annotations
import hashlib,json,os,struct,sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote,urlsplit
from urllib.request import Request,urlopen

BASE="https://r2.houseofkublai.com"
KEY="bo3/DUMP/zone/base.xpak"
EXPECTED_BYTES=15544877056
HEADER_SIZE=0x78
HASH_ENTRY_SIZE=24

def range_read(key:str,start:int,size:int,expected_bytes:int=EXPECTED_BYTES)->bytes:
    if key!=KEY or start<0 or size<=0 or start+size>expected_bytes:
        raise ValueError("T7 R2 byte range not within original base.xpak")
    request=Request(BASE+"/"+quote(key,safe="/"),headers={
        "Range":f"bytes={start}-{start+size-1}",
        "Accept-Encoding":"identity",
        "User-Agent":"r2-runners-bo3-exact-source-range/1.0",
    })
    with urlopen(request,timeout=120) as response:
        if urlsplit(response.url).hostname!=urlsplit(BASE).hostname:
            raise ValueError("Unexpected R2 redirect origin")
        if response.status !=206:
            raise ValueError(f"Range request ignored: HTTP {response.status}")
        expected=f"bytes {start}-{start+size-1}/{expected_bytes}"
        if response.headers.get("Content-Range")!=expected:
            raise ValueError(f"Original range identity mismatch: {response.headers.get('Content-Range')} != {expected}")
        payload=response.read(size+1)
        if len(payload)!=size:
            raise ValueError(f"R2 range returned {len(payload)} instead of {size} source bytes")
        return payload

def read_base_index()->tuple[dict,dict[int,tuple[int,int]]]:
    header=range_read(KEY,0,HEADER_SIZE)
    if header[:4]!=b"KAPI":raise ValueError("Original base.xpak is not KAPI")
    version=struct.unpack_from("<H",header,6)[0]
    if version!=10:raise ValueError(f"Unsupported original BO3 KAPI version {version}")
    declared=struct.unpack_from("<Q",header,0x10)[0]
    if declared!=EXPECTED_BYTES:raise ValueError("Original KAPI byte length changed")
    data_offset,data_bytes,count,hash_offset,hash_bytes=struct.unpack_from("<QQQQQ",header,0x20)
    if hash_bytes!=count*HASH_ENTRY_SIZE or count>10_000_000:
        raise ValueError("KAPI hash record count inconsistent")
    if data_offset>declared or data_bytes>declared-data_offset:
        raise ValueError("KAPI source data range outside object")
    if hash_offset>declared or hash_bytes>declared-hash_offset:
        raise ValueError("KAPI index range outside original object")
    # Read the entire exact source index in chunks, protecting memory.
    entries={}
    bad=[]
    duplicates=0
    flags=Counter()
    first=[]
    last=[]
    sha=hashlib.sha256()
    step=4*1024*1024
    buffer=b""
    for offset in range(0,hash_bytes,step):
        at=hash_offset+offset
        body=range_read(KEY,at,min(step,hash_bytes-offset))
        sha.update(body)
        buffer+=body
        full=len(buffer)//HASH_ENTRY_SIZE
        for i in range(full):
            key,pos,raw_size=struct.unpack_from("<QQQ",buffer,i*HASH_ENTRY_SIZE)
            packed=raw_size&0x00ff_ffff_ffff_ffff
            flags[raw_size>>56]+=1
            if pos>data_bytes or packed>data_bytes-pos:
                bad.append({"index":(offset//HASH_ENTRY_SIZE)+i,"position":pos,"packed":packed})
                if len(bad)>5:raise ValueError("Corrupt KAPI index entries")
            if key in entries:
                duplicates+=1
            else:
                entries[key]=(pos,packed)
            record={"key":f"0x{key:016x}","offset":pos,"packed_bytes":packed}
            if len(first)<5:first.append(record)
            last.append(record)
            if len(last)>5:last.pop(0)
        buffer=buffer[full*HASH_ENTRY_SIZE:]
    if buffer:raise ValueError("Partial BO3 KAPI hash record at index end")
    if bad:raise ValueError(f"Out-of-bounds KAPI records: {bad[:3]}")
    if duplicates:raise ValueError(f"{duplicates} repeated original KAPI source keys")
    return {
        "key":KEY,"file_bytes":EXPECTED_BYTES,
        "header_version":version,
        "data_offset":data_offset,"data_bytes":data_bytes,
        "hash_offset":hash_offset,"hash_bytes":hash_bytes,
        "hash_count":count,"unique_hashes":len(entries),
        "hash_index_sha256":sha.hexdigest(),
        "size_flag_counts":dict(flags),
        "first_entries":first,"last_entries":last,
    },entries

def main():
    meta,entries=read_base_index()
    print(json.dumps(meta,sort_keys=True),flush=True)
    output=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    output.mkdir(parents=True,exist_ok=True)
    (output/"bo3_base_exact_source_index.json").write_text(json.dumps(meta,indent=2)+"\n",encoding="utf-8")
    print(f"Authenticated complete source hash index: {len(entries)} keys",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as error:
        print(f"BO3 retail base.xpak index failure: {error}",file=sys.stderr)
        sys.exit(1)
