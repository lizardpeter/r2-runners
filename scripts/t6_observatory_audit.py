#!/usr/bin/env python3
"""Authentic retail T6 FastFile evidence -> source-observatory/v1 metadata JSON.

Invoked on an isolated networked runner after source SHA256 verification and
independent C expander. Source bytes are not committed or embedded in reports.
A complete XAsset DIRECTORY walk is not asset-body / byte-semantic closure.
"""
import argparse, collections, hashlib, json, struct, sys
from pathlib import Path

def sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def spans_and_records(data, parser):
    if len(data)<64: raise ValueError("expanded stream shorter than XFile and list headers")
    pos=64
    sc,sp,dc,dp,ac,ap=struct.unpack_from("<6I",data,40)
    regions=[{"start":0,"end":40,"kind":"structural","name":"XFile header / 8 XBlock sizes"},
             {"start":40,"end":64,"kind":"structural","name":"ScriptString, dependency and XAsset directory header"}]
    if sc>2000000 or dc>2000000 or ac>2000000:
        raise ValueError("Unreasonable source count; refuse untrusted allocation")
    if sc:
        if sp!=0xffffffff: raise ValueError("ScriptStringList not inline")
        end=pos+sc*4
        if end>len(data): raise ValueError("script pointer table outside stream")
        ptrs=struct.unpack_from("<"+str(sc)+"I",data,pos)
        regions.append({"start":pos,"end":end,"kind":"structural","name":"ScriptString pointers"})
        pos=end
        begin=pos
        for p in ptrs:
            if p==0xffffffff:
                end=data.find(b"\0",pos)
                if end<0:raise ValueError("unterminated script string")
                pos=end+1
        if pos>begin:regions.append({"start":begin,"end":pos,"kind":"structural","name":"ScriptString bytes"})
    if dc:
        if dp!=0xffffffff:raise ValueError("dependency list not inline")
        end=pos+dc*4
        if end>len(data):raise ValueError("dependency pointer array beyond source")
        ptrs=struct.unpack_from("<"+str(dc)+"I",data,pos)
        regions.append({"start":pos,"end":end,"kind":"structural","name":"Dependency pointers"})
        pos=end
        begin=pos
        for p in ptrs:
            if p==0xffffffff:
                end=data.find(b"\0",pos)
                if end<0:raise ValueError("unterminated dependency string")
                pos=end+1
        if pos>begin:regions.append({"start":begin,"end":pos,"kind":"structural","name":"Dependency string bytes"})
    if ap!=0xffffffff:raise ValueError("XAsset table not inline")
    table_begin=pos
    table_end=pos+ac*8
    if table_end>len(data):raise ValueError("XAsset entries beyond expanded stream")
    records=[]
    counts=collections.Counter()
    for i in range(ac):
        type_id,ptr=struct.unpack_from("<II",data,pos)
        if type_id>=len(parser.ASSET_TYPES):raise ValueError(f"unknown asset type {type_id} at {i}")
        typename=parser.ASSET_TYPES[type_id]
        kind="null" if ptr==0 else "inline" if ptr==0xffffffff else "insert" if ptr==0xfffffffe else "packed-reference"
        records.append({"ordinal":i,"type_id":type_id,"type":typename,
                        "expanded_start":pos,"expanded_end":pos+8,"pointer_kind":kind,
                        "body_decoded":False})
        counts[typename]+=1
        pos+=8
    regions.append({"start":table_begin,"end":table_end,"kind":"structural","name":"XAsset type/pointer directory"})
    if pos<len(data):
        regions.append({"start":pos,"end":len(data),"kind":"unknown","name":"Serialized asset bodies / trailing bytes: not assigned semantically"})
    return regions,records,dict(sorted(counts.items())),pos

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--expanded",type=Path,required=True)
    p.add_argument("--parser",type=Path,required=True)
    p.add_argument("--expected-source-sha256",required=True)
    p.add_argument("--expected-expanded-sha256")
    p.add_argument("--r2-key",required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    if not args.r2_key.startswith("bo2/zone/") or not args.r2_key.endswith(".ff"):
        p.error("exact T6 retail zone key required")
    src_hash=sha256(args.source)
    if src_hash!=args.expected_source_sha256.lower():raise ValueError("Original R2 FastFile hash mismatch")
    expanded_hash=sha256(args.expanded)
    if args.expected_expanded_sha256 and expanded_hash!=args.expected_expanded_sha256.lower():
        raise ValueError("Expanded source SHA256 disagrees with independent retained fixture")
    # Explicitly load pinned public source parser; do not silently switch to private import code.
    import importlib.util
    spec=importlib.util.spec_from_file_location("t6_raw_xasset_inventory",args.parser)
    parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
    data=args.expanded.read_bytes()
    front=parser.parse_front(data)
    regions,records,counts,end=spans_and_records(data,parser)
    if end!=front["asset_body_stream_raw_offset"] or counts!=front["asset_type_counts"]:
        raise ValueError("Independent region walk and pinned parser disagree: fail closed")
    assert sum(x["end"]-x["start"] for x in regions)==len(data)
    assert all(a["end"]==b["start"] for a,b in zip(regions,regions[1:]))
    proof={
        "schema":"source-observatory/t6-expanded/v1",
        "game":"bo2","game_build":"T6 PC retail signed FF / version 147",
        "source":{"r2_key":args.r2_key,"bytes":args.source.stat().st_size,"sha256":src_hash,
                  "sha256_verified_against_pinned_source":True},
        "expanded":{"bytes":len(data),"sha256":expanded_hash,
                    "independent_expected_sha256_matched":bool(args.expected_expanded_sha256),
                    "address_space":"decrypted and raw-DEFLATE-expanded XFile"},
        "parser":{"source":"lizardpeter/bo2-t6-assets public source-pinned t6_raw_xasset_inventory.py",
                  "scope":"XFile header, ScriptStringList, dependency pointers/strings, XAsset directory ONLY"},
        "xfile":{"declared_zone_size":front["declared_zone_size"],
                 "declared_external_size":front["declared_external_size"],
                 "block_sizes":front["block_sizes"],
                 "script_strings":front["script_string_count"],
                 "dependencies":front["dependency_count"],
                 "asset_count":front["asset_count"],
                 "xasset_array_offset":front["asset_array_raw_offset"],
                 "asset_body_stream_offset":end},
        "type_counts":counts,"asset_records":records,
        "expanded_ranges":regions,
        "coverage":{"outer_file":"encrypted signed FF decoded to XFile",
                    "directory":"validated",
                    "known_structural_expanded_bytes":end,
                    "semantic_asset_body_bytes":0,
                    "unclassified_expanded_bytes":len(data)-end,
                    "asset_bodies":"not-evaluated",
                    "production_rust_importer":"not-tested",
                    "semantic_complete":False,
                    "byte_complete":False},
        "proof_boundary":"Only parsed directory bytes are counted structurally. Body bytes unclassified, not understood. Physical source and expanded XFile offsets cannot be conflated."
    }
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps({"source":args.r2_key,"types":len(counts),"assets":len(records),
                      "expanded_bytes":len(data),"directory_end":end,
                      "structural_share_percent":round(100*end/max(1,len(data)),5)}))
if __name__=="__main__":
    try:main()
    except Exception as e:
        print("FAIL-CLOSED T6 AUDIT: "+str(e),file=sys.stderr)
        sys.exit(1)
