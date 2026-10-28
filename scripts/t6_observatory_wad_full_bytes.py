#!/usr/bin/env python3
"""Full original-byte and zlib-stream WAD accounting; no local PC required.

Original sources are the explicit 366 R2 objects. Every physical byte must
belong to the header, 44-byte directory entry table, or an indexed compressed
zlib payload. The nested content is decoded losslessly and hashed, but
script/gameplay semantics are NOT inferred from decompression alone.
"""
import argparse,hashlib,json,struct,time,zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from urllib.parse import quote,urlsplit
from urllib.request import Request,urlopen

R2="https://r2.houseofkublai.com/"
ENTRY=44
MAGIC=b"T3w\xab"

def download_exact(key,expected):
    if not key.startswith("bo2/") or not key.endswith(".wad"):
        raise ValueError("Bad source object key")
    url=R2+quote(key,safe="/")
    for attempt in range(3):
        try:
            req=Request(url,headers={"User-Agent":"r2-runners/t6-wad-exact-byte/1","Accept-Encoding":"identity"})
            with urlopen(req,timeout=50) as r:
                if urlsplit(r.url).hostname!="r2.houseofkublai.com" or r.status!=200:
                    raise ValueError("Source response not an original R2 200 body")
                length=r.headers.get("Content-Length")
                if length and int(length)!=expected:
                    raise ValueError("R2 original byte length disagrees with pinned manifest")
                data=r.read(expected+1)
            if len(data)!=expected:raise ValueError("Original source byte length differs")
            return data
        except Exception:
            if attempt==2:raise
            time.sleep(1+attempt)
    raise AssertionError("unreachable")

def audit(row):
    key,length=row["source_key"],row["original_r2_size"]
    out={"source_key":key,"original_r2_size":length,"state":"download_pending"}
    try:
        raw=download_exact(key,length)
        out["source_sha256"]=hashlib.sha256(raw).hexdigest()
        if raw[:4]!=MAGIC:raise ValueError("Not T3w original")
        ts,n,ffotd=struct.unpack_from(">III",raw,4)
        if n!=row["entry_count"] or ffotd!=row["ffotd_version"]:
            raise ValueError("Full source header differs from separately authenticated R2 range index")
        table_end=16+44*n
        table=raw[16:table_end]
        if len(table)!=44*n or hashlib.sha256(table).hexdigest()!=row["entry_table_sha256"]:
            raise ValueError("Full original WAD entry table SHA mismatch against independent range proof")
        ranges=[(0,16,"wad_header"),(16,table_end,"wad_directory")]
        inner=[]
        codec_ok=0
        json_ok=0
        json_invalid=0
        expanded_total=0
        for idx in range(n):
            pos=44*idx
            filename=table[pos:pos+32].split(b"\x00",1)[0].decode("latin-1")
            csz,decl,offset=struct.unpack_from(">III",table,pos+32)
            if offset<table_end or csz==0 or offset+csz>length:
                raise ValueError(f"Invalid compressed entry span for ordinal {idx}")
            ranges.append((offset,offset+csz,"compressed_payload"))
            compressed=raw[offset:offset+csz]
            z=zlib.decompressobj()
            plain=z.decompress(compressed,decl+1)
            plain+=z.flush()
            if not z.eof or z.unused_data or z.unconsumed_tail or len(plain)!=decl:
                raise ValueError(f"Original WAD zlib entry invalid at ordinal {idx} {filename!r}")
            codec_ok+=1;expanded_total+=len(plain)
            nested={"ordinal":idx,"name":filename,"original_offset":offset,
                    "compressed_bytes":csz,"expanded_bytes":len(plain),
                    "expanded_sha256":hashlib.sha256(plain).hexdigest(),
                    "zlib_complete":True,"semantic_complete":False}
            if filename.lower().endswith(".json"):
                try:
                    obj=json.loads(plain.decode("utf-8-sig"))
                    json_ok+=1
                    nested["json_syntax"]="valid"
                    nested["json_root_type"]=type(obj).__name__
                except Exception as e:
                    json_invalid+=1
                    nested["json_syntax"]="invalid"
                    nested["json_parse_error"]=str(e)[:100]
            inner.append(nested)
        ranges.sort()
        prev=0
        gaps=[]
        overlaps=[]
        for start,end,owner in ranges:
            if start>prev:gaps.append([prev,start])
            if start<prev:overlaps.append([start,min(prev,end)])
            prev=max(prev,end)
        if prev<length:gaps.append([prev,length])
        if overlaps:raise ValueError(f"Source ranges overlap: {overlaps[:4]}")
        if gaps:raise ValueError(f"Source leaves physical unknown gaps: {gaps[:4]}")
        out.update(state="full_original_wad_byte_ownership_and_zlib_verified",
          timestamp_seconds=ts,ffotd_version=ffotd,
          directory_entries=n,source_fully_accounted_bytes=length,
          physical_gaps=0,physical_overlaps=0,
          header_bytes=16,directory_bytes=len(table),
          compressed_bytes=sum(x["compressed_bytes"] for x in inner),
          zlib_streams_verified=codec_ok,
          expanded_total_bytes=expanded_total,
          json_syntax_valid=json_ok,json_syntax_invalid=json_invalid,
          nested_entries=inner,
          semantic_complete=False,
          proof_boundary="Full exact original source bytes SHA256-hashed and partitioned into header/table/compressed payload. All zlib bodies losslessly decoded & hashed. JSON syntax where applicable validated. Other embedded content semantics and gameplay execution not established.")
    except Exception as e:
        out.update(state="original_or_nested_wad_failure",error=str(e)[:700])
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--indexes",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--workers",type=int,default=12)
    a=p.parse_args()
    source=json.loads(a.indexes.read_text())
    if source["schema"]!="source-observatory/t6-wad-index/v1" or source["indexes_validated"]!=366:
        raise ValueError("Only exhaustive original R2 table proofs may seed this audit")
    with ThreadPoolExecutor(max_workers=min(16,max(1,a.workers))) as pool:
        tasks=[pool.submit(audit,row) for row in source["files"]]
        files=sorted((f.result() for f in as_completed(tasks)),key=lambda f:f["source_key"])
    states=dict(Counter(f["state"] for f in files))
    good=[f for f in files if f["state"]=="full_original_wad_byte_ownership_and_zlib_verified"]
    out={"schema":"source-observatory/t6-wad-full-byte-accounting/v1",
         "original_wad_files":len(files),
         "original_files_full_hash_verified":sum(bool(f.get("source_sha256")) for f in files),
         "full_physical_source_byte_coverage_count":len(good),
         "all_zlib_entries_complete_count":sum(f.get("zlib_streams_verified",0) for f in good),
         "all_zlib_expanded_bytes":sum(f.get("expanded_total_bytes",0) for f in good),
         "original_owned_physical_bytes":sum(f.get("source_fully_accounted_bytes",0) for f in good),
         "json_syntax_valid_total":sum(f.get("json_syntax_valid",0) for f in good),
         "json_syntax_invalid_total":sum(f.get("json_syntax_invalid",0) for f in good),
         "state_counts":states,
         "semantic_complete":False,
         "proof_boundary":"Physical byte ownership and zlib transport decode are source-complete for passing WADs, not game/application semantic completion for embedded files.",
         "files":files}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({k:v for k,v in out.items() if k not in ("files","proof_boundary")},indent=2))
    if len(good)!=366:raise RuntimeError("Full WAD byte ownership not verified for all 366; per-file blockers retained")
if __name__=="__main__":main()
