#!/usr/bin/env python3
"""Original-source T6 unsigned PC/PS3/WiiU server FastFile corpus.

A separate unsigned transport path is source-proven for all 3 platforms.
Do not conflate this with signed PC client FastFile semantics.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

def module(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m

def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda:f.read(1<<20),b""):h.update(data)
    return h.hexdigest()

def audit(item,work,downloader,decoder,parser):
    key=item["r2_key"]
    platform=item["platform"]
    expected={"ps3":146,"xbox360":146,"pc":147,"wiiu":148}[platform]
    row={"source_key":key,"platform":platform,"expected_version":expected,
         "original_listed_bytes":item["r2_listed_bytes"],"state":"source_pending",
         "proof_boundary":"Unsigned XChunk transport decode differs from structural XFile parsing and does not demonstrate semantic XAsset body understanding"}
    proc=subprocess.run([sys.executable,str(downloader),
             "--base-url","https://r2.houseofkublai.com",
             "--key",key,"--expected-size",str(item["r2_listed_bytes"]),
             "--output-dir",str(work)],capture_output=True,text=True,timeout=300)
    if proc.returncode:
        row.update(state="source_fetch_failed",error=(proc.stderr or proc.stdout)[-500:])
        return row
    source=work/"artifact"/Path(key)
    row["original_sha256"]=sha256(source)
    raw=source.read_bytes()
    if raw[:8]!=b"TAsvu100" or int.from_bytes(raw[8:12],"little")!=expected:
        row.update(state="signature_or_version_conflict",error="Original source header differs from independently surveyed platform/version")
        return row
    try:
        expanded,proof=decoder.decode(raw)
    except Exception as ex:
        row.update(state="unsigned_chunk_decode_failed",error=str(ex)[:600])
        return row
    row.update(state="unsigned_xchunks_decoded",original_authenticated_bytes=len(raw),
      unsigned_chunks=proof["chunk_count"],
      original_xchunks_consumed_bytes=proof["consumed_bytes_including_zero_chunk"],
      original_trailing_bytes=proof["trailing_bytes"],
      original_trailing_all_zero=proof["trailing_all_zero"],
      expanded_bytes=len(expanded),expanded_sha256=hashlib.sha256(expanded).hexdigest())
    try:
        front=parser.parse_front(expanded)
        if front["asset_body_stream_raw_offset"]>len(expanded):raise ValueError("Invalid XAsset offset")
        row.update(state="xasset_directory_validated",xasset_count=front["asset_count"],
                   type_counts=front["asset_type_counts"],script_strings=front["script_string_count"],
                   dependencies=front["dependency_count"],
                   expanded_directory_bytes=front["asset_body_stream_raw_offset"],
                   expanded_unknown_bytes=len(expanded)-front["asset_body_stream_raw_offset"])
    except Exception as ex:
        row.update(state="unsigned_xchunks_decoded_directory_unresolved",
                   error=str(ex)[:600],expanded_directory_bytes=0,
                   expanded_unknown_bytes=len(expanded))
    return row

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signatures",type=Path,required=True)
    p.add_argument("--parser",type=Path,required=True)
    p.add_argument("--unsigned-reader",type=Path,required=True)
    p.add_argument("--downloader",type=Path,required=True)
    p.add_argument("--shard",type=int,required=True)
    p.add_argument("--shards",type=int,default=12)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not 0<=a.shard<a.shards:p.error("bad shard")
    signatures=json.loads(a.signatures.read_text())
    if signatures.get("schema")!="source-observatory/t6-header-survey/v1" or not signatures.get("complete_range_survey"):
        raise ValueError("Input signature survey incomplete")
    rows=[]
    for f in signatures["files"]:
        if f["signature_status"]!="t6_dedicated_server_magic_tasvu100":continue
        key=f["r2_key"]
        platform="ps3" if "/PS3 Server/" in key else "xbox360" if "/Xbox 360 Server/" in key else "wiiu" if "/WiiU Server/" in key else "pc" if "/PC Server/" in key else None
        if not platform:raise ValueError("Unsigned source without verifiable platform provenance")
        if f["version"]!={"ps3":146,"xbox360":146,"pc":147,"wiiu":148}[platform]:
            raise ValueError("Contradictory platform and unsigned FF version")
        rows.append({**f,"platform":platform})
    rows.sort(key=lambda f:f["r2_key"])
    if len(rows)!=356:raise ValueError(f"Expected 356 unsigned server originals; received {len(rows)}")
    reader=module(a.unsigned_reader,"unsigned_t6")
    parser=module(a.parser,"t6_xassets")
    out=[]
    with tempfile.TemporaryDirectory(prefix="t6-unsigned-") as tmp:
        root=Path(tmp)
        for i,f in enumerate(rows):
            if i%a.shards!=a.shard:continue
            work=root/"one"
            work.mkdir(exist_ok=True)
            try: result=audit(f,work,a.downloader,reader,parser)
            except Exception as exc:
                result={"source_key":f["r2_key"],"platform":f["platform"],"original_listed_bytes":f["r2_listed_bytes"],
                        "state":"audit_error","error":str(exc)[:600]}
            out.append(result)
            print(json.dumps({"source":result["source_key"],"state":result["state"],"assets":result.get("xasset_count"),"expanded":result.get("expanded_bytes")}),flush=True)
            shutil.rmtree(work,ignore_errors=True)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps({"schema":"source-observatory/t6-server-shard/v1",
        "shard":a.shard,"shards":a.shards,"results":out},indent=2)+"\n")
    print("Audited",len(out),"original sources; report",a.output)

if __name__=="__main__":main()
