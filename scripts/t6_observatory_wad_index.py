#!/usr/bin/env python3
"""Validate original T3w WAD directory structure via authenticated R2 ranges.

Reference format: uhhashe/wadify public source (src/main.cpp),
big-endian 16-byte header followed by fixed 44-byte name/size/offset entries.
No WAD body is decompressed, executed or exposed.
"""
import argparse,hashlib,importlib.util,json,struct
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path

MAGIC=b"T3w\xab"
ENTRY=44

def check(f,reader):
    key,length=f["r2_key"],f["r2_size"]
    proof={"source_key":key,"original_r2_size":length,
           "status":"pending","complete_original_sha256":"not_hash_verified",
           "proof_boundary":"Original R2 WAD header and entry table byte ranges checked; zlib compressed payloads not retrieved or decoded."}
    try:
        head=reader.getrange(key,length,0,16)
        if head[:4]!=MAGIC:raise ValueError("Not T3w\xab source header")
        stamp,n,vers=struct.unpack_from(">III",head,4)
        if n>1_000_000 or 16+n*ENTRY>length:
            raise ValueError("WAD entry count exceeds declared source file")
        directory=reader.getrange(key,length,16,n*ENTRY)
        entries=[]
        total_original=0
        total_compressed=0
        names=set();duplicate_names=0
        for i in range(n):
            b=i*ENTRY
            raw=directory[b:b+32]
            name=raw.split(b"\x00",1)[0].decode("latin-1")
            compressed,size,offset=struct.unpack_from(">III",directory,b+32)
            if not name:raise ValueError(f"Empty name in entry {i}")
            if offset<16+n*ENTRY or offset+compressed>length:
                raise ValueError(f"Entry {i} compressed range escapes source or overlaps directory")
            if name in names:duplicate_names+=1
            names.add(name)
            total_original+=size
            total_compressed+=compressed
            if i<128:
                entries.append({"ordinal":i,"name":name,"compressed_bytes":compressed,
                                "expanded_declared_bytes":size,"source_offset":offset})
        proof.update(status="wad_directory_validated",
             header_magic="T3w\\xAB",big_endian_header=True,
             timestamp_seconds=stamp,
             entry_count=n,ffotd_version=vers,
             entry_table_offset=16,entry_record_bytes=ENTRY,
             entry_table_bytes=len(directory),
             entry_table_sha256=hashlib.sha256(directory).hexdigest(),
             declared_expanded_bytes=sum(x["expanded_declared_bytes"] for x in entries) if len(entries)==n else total_original,
             compressed_payload_bytes_summed=total_compressed,
             duplicate_names=duplicate_names,
             entries_sample=entries,
             entries_sample_truncated=n>128,
             compressed_bodies="not_examined")
    except Exception as ex:
        proof.update(status="wad_directory_invalid_or_unverified",error=str(ex)[:650])
    return proof

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--headers",type=Path,required=True)
    p.add_argument("--reader",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--workers",type=int,default=10)
    a=p.parse_args()
    source=json.loads(a.headers.read_text())
    if source["schema"]!="source-observatory/original-r2-signature-corpus/v1" or not source["complete_signature_survey"]:
        raise ValueError("The whole R2 source signature list is not verified")
    rows=[x for x in source["files"] if x["extension"]=="wad"]
    if len(rows)!=366:raise ValueError("Expected 366 original R2 T6 WADs")
    spec=importlib.util.spec_from_file_location("r2_range_reader",a.reader)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    with ThreadPoolExecutor(max_workers=max(1,min(a.workers,16))) as pool:
        futures=[pool.submit(check,row,reader) for row in rows]
        results=sorted((f.result() for f in as_completed(futures)),key=lambda x:x["source_key"])
    states=dict(Counter(f["status"] for f in results))
    out={"schema":"source-observatory/t6-wad-index/v1",
         "source_files":len(results),"indexes_validated":states.get("wad_directory_validated",0),
         "total_nested_wad_entries":sum(f.get("entry_count",0) for f in results),
         "state_counts":states,"semantic_complete":False,
         "reference":"https://github.com/uhhashe/wadify/blob/main/src/main.cpp",
         "proof_boundary":"Original T3w source WAD directories use big-endian 16-byte headers/44-byte entries. Only original R2 ranges verified, no source-full hash or entry payload Zlib decompression performed. File type identity does not prove semantic body closure.",
         "files":results}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({k:v for k,v in out.items() if k not in ("files","proof_boundary")},indent=2))
    if out["indexes_validated"]!=366:
        raise RuntimeError("Some WAD directory records rejected, retained in metadata for investigation")
if __name__=="__main__":main()
