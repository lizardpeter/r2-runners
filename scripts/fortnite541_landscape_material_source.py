#!/usr/bin/env python3
"""Exact 5.41 authored Athena landscape material/function source handoff.

Only authenticated, uncompressed original PAK v7 entries are accepted.
Paths, byte lengths and SHA-1 are all retained, and the original files
are shipped unchanged. Missing/ambiguous requested originals fail.
"""
from __future__ import annotations
from pathlib import Path
import argparse,json
from fortnite541_dependency_handoff import authenticated_archive_index,fetch_verified,PREFIX

REQUIRED=(
 "athena/environments/landscape/material/m_athena_terrain_master",
 "athena/environments/landscape/materialfunctions/standard/mf_athena_forest_01",
 "athena/environments/landscape/materialfunctions/standard/mf_athena_mud_01",
 "athena/environments/landscape/materialfunctions/standard/mf_athena_gravel_01",
 "athena/environments/landscape/materialfunctions/standard/mf_athena_road_01",
 "athena/environments/landscape/materialfunctions/arid/mf_athena_arid_sand",
)
# Enumerate additional source functions by fully-authenticated PAK index
# rather than guessing which classes or material calls exist.
FUNCTION_PREFIXES=(
 "athena/environments/landscape/materialfunctions/",
)
def discover(index):
    names=set(REQUIRED)
    for key in index:
        if not key.endswith(".uasset"):continue
        stem=key[:-7]
        if any(stem.startswith(x) for x in FUNCTION_PREFIXES):
            names.add(stem)
    return sorted(names)
def run(out:Path,report:Path):
    base,ranged,index,index_proofs=authenticated_archive_index()
    out.mkdir(parents=True,exist_ok=True)
    report.mkdir(parents=True,exist_ok=True)
    records=[];unresolved=[]
    stems=discover(index)
    for stem in stems:
        files=[]
        for ext in (".uasset",".uexp",".ubulk"):
            identity=stem+ext
            candidates=index.get(identity,[])
            different={(x[2][2],x[2][4]) for x in candidates}
            if len(different)>1:
                unresolved.append({"identity":identity,"error":"ambiguous authenticated original source owners"})
                continue
            if not candidates:
                if ext!=".ubulk":
                    unresolved.append({"identity":identity,"error":"no authenticated source"})
                continue
            chosen=sorted(candidates,key=lambda v:(v[0],v[1]))[0]
            original=chosen[1].replace("\\","/").lstrip("/")
            lower=original.lower()
            at=lower.find(PREFIX.lower())
            if at>=0: relative=original[at:]
            elif lower.startswith("content/"):relative="FortniteGame/"+original
            else:relative=PREFIX+original
            # No arbitrary size caps. This is original byte-level dependency
            # handoff, not a reduced JSON-only reconstruction.
            try:
                item=fetch_verified(chosen,out/relative,base,ranged)
                item["original_path"]=relative
                item["archive"]=chosen[0]
                records.append(item)
                files.append(relative)
                print("ATHENA_ORIGINAL_MATERIAL_FILE",relative,item["bytes"],item["sha1"],flush=True)
            except Exception as ex:
                unresolved.append({"identity":identity,"error":str(ex)})
        print("ATHENA_ORIGINAL_MATERIAL_PACKAGE",stem,len(files),flush=True)
    meta={"requested_or_discovered_package_stems":stems,
        "verified_source_files":records,"unresolved":unresolved,
        "authenticated_indexes":index_proofs,
        "verified_original_bytes":sum(x["bytes"] for x in records)}
    (report/"original-material-function-source.json").write_text(json.dumps(meta,indent=2)+"\n")
    print("ATHENA_SOURCE_MATERIAL_HANDOFF",len(stems),len(records),len(unresolved),meta["verified_original_bytes"],flush=True)
    if unresolved:raise RuntimeError("missing or ambiguous exact original material files (see attached provenance)")
def test():
    assert all(x.lower()==x for x in REQUIRED)
    x={REQUIRED[0]+".uasset":[],"athena/environments/landscape/materialfunctions/standard/a.uasset":[]}
    assert len(discover(x))==len(REQUIRED)+1
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path)
    p.add_argument("--report",type=Path)
    p.add_argument("--self-test",action="store_true")
    x=p.parse_args()
    test()
    if not x.self_test:run(x.output,x.report)
