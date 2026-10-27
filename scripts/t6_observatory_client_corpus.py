#!/usr/bin/env python3
"""Scan the entire verified T6 client FastFile source list on remote runners.

Each file gets SHA-256 of fetched R2 source; when possible, decode all XChunks,
hash expanded bytes, and walk the original XAsset directory. Unknown body bytes
remain unknown. Every per-file failure is recorded without pretending success.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

SCHEMA = "source-observatory/t6-client-corpus-shard/v1"

def sha256(path):
    d=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            d.update(chunk)
    return d.hexdigest()

def load_parser(path):
    spec=importlib.util.spec_from_file_location("t6_raw_xasset_inventory",path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def audit_row(f, parser, expander, downloader, work):
    key=f["r2_key"]
    if not key.startswith(("bo2/zone/all/","bo2/zone/english/")) or not key.endswith(".ff"):
        raise ValueError("Input includes an unexpected non-client-zone source")
    result={"source_key":key,"original_listed_bytes":f["r2_listed_bytes"],
            "signature":f["signature_status"],"version":f["version"],
            "state":"fetch_pending",
            "proof_boundary":"Physical file hash verified during this run only; expanded bytes structurally inventoried, asset bodies not semantically decoded"}
    if f["signature_status"]!="t6_pc_signed_header" or f["version"]!=147:
        result.update(state="unsupported_magic",error="Header survey was not a signed PC v147 zone")
        return result
    name=Path(key).stem
    output=work/"download"
    proc=subprocess.run([sys.executable,str(downloader),"--base-url","https://r2.houseofkublai.com",
                         "--key",key,"--expected-size",str(f["r2_listed_bytes"]),
                         "--output-dir",str(output)],text=True,capture_output=True,timeout=300)
    if proc.returncode!=0:
        result.update(state="source_fetch_failed",error=(proc.stderr or proc.stdout)[-650:])
        return result
    source=output/"artifact"/Path(key)
    result["original_sha256"]=sha256(source)
    result["actual_original_bytes"]=source.stat().st_size
    dest=work/"expanded.bin"
    exp=subprocess.run([str(expander),str(source),str(dest),name],
                       capture_output=True,text=True,timeout=300)
    result["expander_log_tail"]=(exp.stderr or "")[-450:]
    if exp.returncode!=0:
        result.update(state="decode_failed",error=(exp.stderr or exp.stdout)[-700:])
        return result
    result["expanded_sha256"]=sha256(dest)
    result["expanded_bytes"]=dest.stat().st_size
    if dest.stat().st_size==0:
        result.update(state="empty_expanded_stream",xasset_count=0,type_counts={},
                      unknown_expanded_bytes=0,structural_expanded_bytes=0,
                      detail="The authenticated signed file expands to zero serialized XFile bytes; no asset directory exists to parse.")
        return result
    try:
        data=dest.read_bytes()
        p=parser.parse_front(data)
        directory_end=p["asset_body_stream_raw_offset"]
        if not (0 <= directory_end <= len(data)):raise ValueError("directory end out of range")
        result.update(state="xasset_directory_validated",
                      xasset_count=p["asset_count"],type_counts=p["asset_type_counts"],
                      script_strings=p["script_string_count"],dependencies=p["dependency_count"],
                      asset_body_stream_offset=directory_end,
                      structural_expanded_bytes=directory_end,
                      unknown_expanded_bytes=len(data)-directory_end)
    except Exception as ex:
        result.update(state="front_parse_failed",error=str(ex)[:650],
                      structural_expanded_bytes=0,
                      unknown_expanded_bytes=dest.stat().st_size)
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signatures",type=Path,required=True)
    p.add_argument("--expander",type=Path,required=True)
    p.add_argument("--parser",type=Path,required=True)
    p.add_argument("--downloader",type=Path,required=True)
    p.add_argument("--shard",type=int,required=True)
    p.add_argument("--shards",type=int,default=12)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    if not 0<=args.shard<args.shards: p.error("shard outside range")
    survey=json.loads(args.signatures.read_text())
    if survey["schema"]!="source-observatory/t6-header-survey/v1" or not survey["complete_range_survey"]:
        raise ValueError("Reject incomplete or unverified original R2 signature source")
    sources=sorted((x for x in survey["files"] if x["signature_status"]=="t6_pc_signed_header"),key=lambda x:x["r2_key"])
    if len(sources)!=215:raise ValueError(f"unexpected signed-client corpus size: {len(sources)}")
    parser=load_parser(args.parser)
    output=[]
    with tempfile.TemporaryDirectory(prefix="t6-audit-") as tmp:
        root=Path(tmp)
        for idx, row in enumerate(sources):
            if idx%args.shards!=args.shard:continue
            work=root/"one"
            work.mkdir(parents=True,exist_ok=True)
            try:
                proof=audit_row(row,parser,args.expander,args.downloader,work)
            except Exception as ex:
                proof={"source_key":row["r2_key"],"original_listed_bytes":row["r2_listed_bytes"],
                       "state":"audit_error","error":str(ex)[:650]}
            output.append(proof)
            print(json.dumps({"source":proof["source_key"],"state":proof["state"],
                              "xassets":proof.get("xasset_count"),"expanded":proof.get("expanded_bytes")}),flush=True)
            import shutil
            shutil.rmtree(work,ignore_errors=True)
    record={"schema":SCHEMA,"shard":args.shard,"shards":args.shards,
            "client_files_considered":len(sources),
            "corpus_scope":"215 original client v147 zones, excludes 356 dedicated-server zones",
            "results":output}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(record,indent=2)+"\n")
    print("written",args.output,"files",len(output))

if __name__=="__main__":main()
