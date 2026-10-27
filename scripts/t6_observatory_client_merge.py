#!/usr/bin/env python3
"""Combine complete T6 client-shard reports without upgrading parser claims."""
import argparse
from collections import Counter
import json
from pathlib import Path

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--shards",type=Path,required=True)
    a.add_argument("--headers",type=Path,required=True)
    a.add_argument("--output",type=Path,required=True)
    a.add_argument("--shard-count",type=int,default=12)
    args=a.parse_args()
    hdr=json.loads(args.headers.read_text())
    if hdr["schema"]!="source-observatory/t6-header-survey/v1" or not hdr["complete_range_survey"]:
        raise ValueError("No completed original-source header evidence")
    expected={f["r2_key"]:f for f in hdr["files"] if f["signature_status"]=="t6_pc_signed_header"}
    if len(expected)!=215:raise ValueError("Expected exactly 215 client FastFiles")
    files=sorted(args.shards.rglob("t6-client-shard-*.json"))
    if len(files)!=args.shard_count:raise ValueError(f"Only {len(files)} of {args.shard_count} completed shard files")
    merged={}
    seen_shards=set()
    for path in files:
        obj=json.loads(path.read_text())
        if obj["schema"]!="source-observatory/t6-client-corpus-shard/v1" or obj["shards"]!=args.shard_count:
            raise ValueError("Unexpected shard schema/plan")
        if obj["shard"] in seen_shards:raise ValueError("Duplicate shard")
        seen_shards.add(obj["shard"])
        for f in obj["results"]:
            key=f["source_key"]
            if key in merged or key not in expected:raise ValueError("Duplicate or unlisted source key: "+key)
            if f["original_listed_bytes"]!=expected[key]["r2_listed_bytes"]:raise ValueError("Source size changed")
            if "structural_expanded_bytes" in f and "expanded_bytes" in f:
                if f["structural_expanded_bytes"]+f["unknown_expanded_bytes"]!=f["expanded_bytes"]:
                    raise ValueError("Byte classification does not partition XFile")
            if f["state"]=="xasset_directory_validated" and sum(f["type_counts"].values())!=f["xasset_count"]:
                raise ValueError("Asset type count inconsistent")
            merged[key]=f
    if len(merged)!=len(expected) or set(merged)!=set(expected):
        raise ValueError(f"Incomplete T6 client corpus: {len(merged)} of {len(expected)}")
    counts=dict(sorted(Counter(f["state"] for f in merged.values()).items()))
    completed=[f for f in merged.values() if f["state"] in ("xasset_directory_validated","empty_expanded_stream")]
    struct=sum(f.get("structural_expanded_bytes",0) for f in completed)
    unknown=sum(f.get("unknown_expanded_bytes",0) for f in completed)
    out={
      "schema":"source-observatory/t6-client-corpus/v1",
      "corpus":"bo2/zone/all/ + bo2/zone/english/; signed original PC FastFiles only",
      "complete_source_listing":True,
      "files_in_corpus":215,
      "header_proven":True,
      "individual_source_hash_proven_count":sum(bool(f.get("original_sha256")) for f in merged.values()),
      "expanded_stream_decoded_count":sum(bool(f.get("expanded_sha256")) for f in merged.values()),
      "xasset_directory_validated_count":counts.get("xasset_directory_validated",0),
      "empty_expanded_stream_count":counts.get("empty_expanded_stream",0),
      "state_counts":counts,
      "asset_directory_entries":sum(f.get("xasset_count",0) for f in completed),
      "expanded_structural_bytes_for_parsed_files":struct,
      "expanded_unknown_bytes_for_parsed_files":unknown,
      "semantic_complete":False,
      "byte_complete":False,
      "proof_boundary":"No full semantic XAsset body ownership claimed. Each successful file is verified against its current original R2 source download SHA256; only three retained historical fixtures have independently pinned expanded SHA256s. Failed and unattempted operations remain explicit.",
      "files":[merged[k] for k in sorted(merged)]
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({k:v for k,v in out.items() if k in ("files_in_corpus","individual_source_hash_proven_count","expanded_stream_decoded_count","xasset_directory_validated_count","empty_expanded_stream_count","state_counts","asset_directory_entries")}))
if __name__=="__main__":main()
