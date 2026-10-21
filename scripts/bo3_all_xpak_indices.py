#!/usr/bin/env python3
"""Inventory exact source KAPI hash indices for every available BO3 XPAK.

Original archives stay remote in R2. Fetch only KAPI header and original hash
table via verified Content-Range; retain index fingerprints and collision
diagnostics, not game payload bytes.
"""
from __future__ import annotations
from collections import defaultdict,Counter
import hashlib,json,os,struct,sys
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request,urlopen

BASE="https://r2.houseofkublai.com/"
PREFIX="bo3/DUMP/zone/"
KNOWN={
    "base.xpak":15544877056,
    "base_patch_tu32.xpak":1048576,
    "core_common.xpak":6291456,
    "core_frontend.xpak":2883584,
    "core_frontend_patch.xpak":4194304,
    "core_gfx.xpak":786432,
    "core_patch.xpak":786432,
    "core_pre_gfx.xpak":786432,
    "core_ui.xpak":1048576,
    "en_base.xpak":46399488,
    "en_core_common.xpak":786432,
    "en_core_frontend.xpak":786432,
    "en_core_frontend_patch.xpak":98304,
    "en_core_specialists.xpak":98304,
    "en_initial.xpak":13893632,
}
MAX_HASHES=10_000_000
def exact_read(name,at,count):
    original=KNOWN[name]
    if count<=0 or at<0 or count>4*1024*1024 or at+count>original:
        raise ValueError("T7 source index range outside known R2 object or safety bounds")
    request=Request(BASE+quote(PREFIX+name,safe="/"),headers={
        "Range":f"bytes={at}-{at+count-1}","Accept-Encoding":"identity",
        "User-Agent":"r2-runners-t7-index-matrix/1",
    })
    with urlopen(request,timeout=110) as res:
        want=f"bytes {at}-{at+count-1}/{original}"
        if res.status!=206 or res.headers.get("Content-Range")!=want:
            raise ValueError(f"Exact BO3 source range refused: {name}@{at} {res.status} {res.headers.get('Content-Range')}")
        content=res.read(count+1)
        if len(content)!=count:raise ValueError("Short/oversized original R2 source range")
        return content

def read_index(name):
    h=exact_read(name,0,0x78)
    if h[:4]!=b"KAPI":raise ValueError(f"Not a KAPI original: {name}")
    version=struct.unpack_from("<H",h,6)[0]
    original=struct.unpack_from("<Q",h,0x10)[0]
    if version!=10 or original!=KNOWN[name]:
        raise ValueError(f"T7 source header changed: {name}, version {version}")
    data_start,data_len,number,table_start,table_len=struct.unpack_from("<QQQQQ",h,0x20)
    if number>MAX_HASHES or number*24!=table_len:
        raise ValueError(f"T7 XPAK hash table inconsistent: {name}")
    if table_start>original or table_len>original-table_start or data_start>original or data_len>original-data_start:
        raise ValueError("T7 XPAK index bounds changed")
    sha=hashlib.sha256()
    keys=set()
    packed=0
    flags=Counter()
    remaining=table_len
    offset=table_start
    overflow=0
    while remaining:
        count=min(remaining,4*1024*1024)
        count-=count%24
        if count<=0:count=remaining
        raw=exact_read(name,offset,count)
        sha.update(raw)
        for key,pos,word in struct.iter_unpack("<QQQ",raw):
            size=word & 0x00ffffffffffffff
            flags[word>>56]+=1
            if pos>data_len or size>data_len-pos:overflow+=1
            if key in keys:raise ValueError(f"Duplicate hash in {name}")
            keys.add(key)
            packed+=size
        remaining-=count
        offset+=count
    if overflow:raise ValueError(f"Out-of-bounds original KAPI hashes in {name}")
    return {
        "archive":name,"original_bytes":original,"version":version,
        "hash_count":number,"hash_index_bytes":table_len,
        "hash_index_sha256":sha.hexdigest(),
        "data_bytes":data_len,"packed_record_bytes_sum":packed,
        "size_flags":dict(sorted(flags.items())),
    },keys

def main():
    all_keys=defaultdict(set)
    reports=[]
    for name in KNOWN:
        report,keys=read_index(name)
        for key in keys:all_keys[key].add(name)
        reports.append(report)
        print(json.dumps(report,sort_keys=True),flush=True)
    duplicates=[(key,sorted(owners)) for key,owners in all_keys.items() if len(owners)>1]
    histogram=Counter()
    for key,owners in all_keys.items():histogram[len(owners)]+=1
    summary={
        "total_kapi_archives":len(reports),
        "unique_hash_keys":len(all_keys),
        "total_hash_records":sum(x["hash_count"] for x in reports),
        "hashes_in_multiple_packages":len(duplicates),
        "multiple_owner_examples":[{"hash":f"0x{h:016x}","packages":p} for h,p in duplicates[:25]],
        "ownership_histogram":dict(histogram),
    }
    print(json.dumps({"summary":summary},sort_keys=True),flush=True)
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    (root/"bo3_exact_xpak_catalog.json").write_text(
        json.dumps({"packages":reports,"summary":summary},indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 exact KAPI index inventory failed: {e}",file=sys.stderr)
        raise SystemExit(1)
