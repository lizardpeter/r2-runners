#!/usr/bin/env python3
"""Unify exact original-server FastFile survey shards without hiding failures."""
import argparse,json
from collections import Counter
from pathlib import Path
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--shards",type=Path,required=True)
    p.add_argument("--headers",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--shard-count",type=int,default=12)
    a=p.parse_args()
    hdr=json.loads(a.headers.read_text())
    if hdr.get("schema")!="source-observatory/t6-header-survey/v1" or not hdr.get("complete_range_survey"):
        raise ValueError("Unverified R2 signature survey")
    exp={f["r2_key"]:f for f in hdr["files"] if f["signature_status"]=="t6_dedicated_server_magic_tasvu100"}
    if len(exp)!=356:raise ValueError("Expected 356 exact original server FastFiles")
    inputs=sorted(a.shards.rglob("t6-server-shard-*.json"))
    if len(inputs)!=a.shard_count:raise ValueError("Missing shard metadata")
    merged={}
    visited=set()
    for inp in inputs:
        j=json.loads(inp.read_text())
        if j["schema"]!="source-observatory/t6-server-shard/v1" or j["shards"]!=a.shard_count:raise ValueError("Bad input shard schema")
        if j["shard"] in visited:raise ValueError("Duplicate shard")
        visited.add(j["shard"])
        for f in j["results"]:
            key=f["source_key"]
            if key in merged or key not in exp:raise ValueError("Extra or duplicate key: "+key)
            if f["original_listed_bytes"]!=exp[key]["r2_listed_bytes"]:raise ValueError("Listed physical size changed")
            if "expanded_bytes" in f and "expanded_unknown_bytes" in f:
                if f["expanded_directory_bytes"]+f["expanded_unknown_bytes"]!=f["expanded_bytes"]:
                    raise ValueError("Mismatched expanded byte partition")
            if f["state"]=="xasset_directory_validated" and sum(f["type_counts"].values())!=f["xasset_count"]:
                raise ValueError("Inconsistent XAsset type counts")
            merged[key]=f
    if set(merged)!=set(exp):raise ValueError(f"Missing {len(exp)-len(merged)} exact original server records")
    states=dict(sorted(Counter(f["state"] for f in merged.values()).items()))
    platforms={}
    for platform in ("pc","ps3","wiiu"):
        xs=[x for x in merged.values() if x["platform"]==platform]
        platforms[platform]={"files":len(xs),"source_hashed":sum(bool(x.get("original_sha256")) for x in xs),
            "expanded":sum(bool(x.get("expanded_sha256")) for x in xs),
            "directory_validated":sum(x["state"]=="xasset_directory_validated" for x in xs),
            "asset_entries":sum(x.get("xasset_count",0) for x in xs),
            "states":dict(sorted(Counter(x["state"] for x in xs).items()))}
    out={"schema":"source-observatory/t6-server-corpus/v1",
         "files_in_corpus":356,"complete_source_listing":True,
         "platforms":platforms,"state_counts":states,
         "source_hashed":sum(bool(x.get("original_sha256")) for x in merged.values()),
         "expanded":sum(bool(x.get("expanded_sha256")) for x in merged.values()),
         "directory_validated":states.get("xasset_directory_validated",0),
         "asset_directory_entries":sum(x.get("xasset_count",0) for x in merged.values()),
         "semantic_complete":False,"byte_complete":False,
         "proof_boundary":"Unsigned source FFs are split by PS3(v146), PC(v147), WiiU(v148). DEFLATE XChunk expansion and XAsset structural directory parsing are separate. Source hashes come from original R2 byte downloads in this audit, not independent historical hash fixtures. No original semantic asset body closure demonstrated.",
         "files":[merged[k] for k in sorted(merged)]}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({k:v for k,v in out.items() if k not in ("files","proof_boundary")},indent=2))
if __name__=="__main__":main()
