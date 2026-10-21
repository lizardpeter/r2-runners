#!/usr/bin/env python3
"""Source-authenticated Athena 5.41 world and environment asset batches.

Read ORIGINAL encrypted PAK v7 indexes, discover packages by authenticated
index paths (never guessed filenames), stream exact package bytes, validate
retail entry SHA-1 and publish a machine-readable source provenance record.
All source-file byte payloads stay on the runner for artifact handoff.
"""
from __future__ import annotations
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import json
from pathlib import Path
import sys

from fortnite541_dependency_handoff import (
    PREFIX, authenticated_archive_index, fetch_verified,
    normalized_content_path,
)

WORLD_ROOTS={
    "poi":("athena/maps/poi/",),
    "streaming":("athena/maps/streaming/",),
    "buildings":("athena/maps/buildings/",),
    "background":("athena/maps/background/","athena/maps/landscape/"),
}
OBJECT_FRAGMENTS={
    "vegetation":("/foliage/","/grass/","/trees/","/tree/","/vegetation/","/plants/","/plant/"),
    "atmosphere":("/sky/","/skydome/","/fog/","/atmosphere/","/cloud/","/weather/","/storm/",
                  "/timeofday/","/lighting/"),
    "terrain":("/landscape/","/terrain/","/biome/","/biomes/"),
}
EXTENSIONS=(".umap",".uasset",".uexp",".ubulk")

def original_relative(internal:str)->str:
    path=internal.replace("\\","/").lstrip("/")
    case=path.lower()
    pos=case.find(PREFIX.lower())
    if pos>=0 and (pos==0 or path[pos-1]=="/"):
        path=path[pos+len(PREFIX):]
    elif case.startswith("content/"):
        path=path[len("Content/"):]
    if not path or path.startswith("/") or any(
        x in ("",".","..") for x in path.split("/")
    ):
        raise ValueError("untrusted retail PAK path")
    return path

def package_family(relative:str,family:str)->bool:
    lower=relative.lower()
    if family in WORLD_ROOTS:
        return lower.endswith(".umap") and any(
            lower.startswith(root) for root in WORLD_ROOTS[family]
        )
    if family in OBJECT_FRAGMENTS:
        return (lower.endswith(".uasset") and
                any(fragment in "/"+lower for fragment in OBJECT_FRAGMENTS[family]))
    raise ValueError("unknown requested Athena source family")

def choose(candidates:list[tuple],identity:str):
    """Only identical authenticated originals may have duplicate ownership."""
    if not candidates:
        return None,"missing"
    hashes={(record[2],record[4]) for _,_,record in candidates}
    if len(hashes)>1:
        return None,"conflicting_authentic_source_payloads"
    return sorted(candidates,key=lambda x:(x[0],x[1]))[0],None

def shards_for_source(stem:str,shards:int)->int:
    return int.from_bytes(hashlib.sha256(stem.lower().encode("utf8")).digest()[:4],"big")%shards

def build_plan(index:dict[str,list[tuple]],family:str,shard:int,shards:int):
    """Return exact retail stem+sidecar files for a deterministic partition."""
    matched=sorted(x for x in index if package_family(x,family))
    report={"family":family,"shard":shard,"shards":shards,
            "authenticated_unique_matched_stems":len(matched),
            "original_package_stems_in_shard":0,"planned_original_files":0,
            "unresolved":[]}
    planned=[]
    stem_ext=".umap" if family in WORLD_ROOTS else ".uasset"
    for base in matched:
        stem=base[:-len(stem_ext)]
        if shards_for_source(stem,shards)!=shard:
            continue
        report["original_package_stems_in_shard"]+=1
        chosen=[]
        for extension in (stem_ext,".uexp",".ubulk"):
            identity=stem+extension
            selection,error=choose(index.get(identity,[]),identity)
            if error and (extension!= ".ubulk" or error!="missing"):
                report["unresolved"].append({"source":identity,"reason":error})
            if selection is not None:
                chosen.append((identity,selection))
        if len(chosen)<2 or any(e not in {k[len(stem):] for k,_ in chosen}
            for e in (stem_ext,".uexp")):
            continue
        planned+=chosen
    report["planned_original_files"]=len(planned)
    return planned,report

def test_logic():
    digest=b"\xaa"*20
    entry=("pakchunk0", "Athena/Maps/POI/Athena_POI_Test_001.umap",
           (100,20,20,0,digest,0))
    base="athena/maps/poi/athena_poi_test_001"
    idx={
        base+".umap":[entry],
        base+".uexp":[("pakchunk0","Athena/Maps/POI/Athena_POI_Test_001.uexp",
                       (200,20,20,0,digest,0))],
    }
    found,report=build_plan(idx,"poi",0,1)
    assert len(found)==2 and not report["unresolved"]
    assert package_family(base+".umap","poi")
    assert not package_family(base+".uexp","poi")
    assert not package_family("athena/maps/poi/Other.uasset","poi")
    assert original_relative("../../../FortniteGame/Content/Athena/Maps/POI/A.umap")=="Athena/Maps/POI/A.umap"
    assert original_relative("Content/Athena/Maps/POI/A.umap")=="Athena/Maps/POI/A.umap"
    assert choose([entry,entry],"x")[1] is None
    bad=("pakchunk1",entry[1],(100,20,20,0,b"\xbb"*20,0))
    assert choose([entry,bad],"x")[1]=="conflicting_authentic_source_payloads"
    print("FORTNITE541_FULL_ATHENA_INDEX_PLAN_TEST_PASS",flush=True)

def run(family:str,shard:int,shards:int,destination:Path,reports:Path):
    base,ranged,index,archives=authenticated_archive_index()
    plan,manifest=build_plan(index,family,shard,shards)
    if not plan:
        raise RuntimeError(f"no authenticated Athena {family} packages in shard {shard}/{shards}")
    report=[]
    failures=[]
    # Preserve exact path casing from the verified original index. Do not
    # flatten files or turn original cooked bytes into metadata-only reports.
    def transfer(item):
        identity,selection=item
        archive,internal,record=selection
        path=destination/PREFIX/original_relative(internal)
        result=fetch_verified(selection,path,base,ranged)
        result["path"]=path.relative_to(destination).as_posix()
        result["source_identity"]=identity
        return result
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures={executor.submit(transfer,item):item[0] for item in plan}
        for future in as_completed(futures):
            try:
                record=future.result()
                report.append(record)
                print("ATHENA_FULL_SOURCE_FILE",record["path"],
                      record["bytes"],record["sha1"],flush=True)
            except Exception as exc:
                failures.append({"source_identity":futures[future],
                                 "status":"download_or_original_sha1_failure",
                                 "reason":str(exc)[:240]})
    manifest["indexed_archives"]=archives
    manifest["verified_files"]=sorted(report,key=lambda x:x["path"])
    manifest["unresolved"].extend(failures)
    manifest["verified_source_bytes"]=sum(x["bytes"] for x in report)
    manifest["verified_file_count"]=len(report)
    manifest["complete"]=not manifest["unresolved"] and len(report)==len(plan)
    manifest["path_prefix"]=PREFIX
    reports.mkdir(parents=True,exist_ok=True)
    (reports/f"athena-{family}-shard-{shard}-authenticated-index.json").write_text(
        json.dumps(manifest,indent=2)+"\n",encoding="utf8")
    print("ATHENA_FULL_SOURCE_BATCH",family,shard,shards,
          "indexed_stems",manifest["authenticated_unique_matched_stems"],
          "planned_files",len(plan),"verified_files",len(report),
          "unresolved",len(manifest["unresolved"]),
          "bytes",manifest["verified_source_bytes"],flush=True)
    if not manifest["complete"]:
        raise RuntimeError("incomplete authenticated Athena source handoff, see report")

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--family",choices=tuple(WORLD_ROOTS)+tuple(OBJECT_FRAGMENTS))
    p.add_argument("--shard",type=int,default=0)
    p.add_argument("--shards",type=int,default=1)
    p.add_argument("--destination",type=Path)
    p.add_argument("--reports",type=Path)
    p.add_argument("--self-test",action="store_true")
    args=p.parse_args()
    test_logic()
    if args.self_test:
        sys.exit(0)
    if not args.family or not args.destination or not args.reports:
        p.error("--family --destination --reports required")
    if args.shards<1 or not 0<=args.shard<args.shards:
        p.error("invalid deterministic shard count/number")
    run(args.family,args.shard,args.shards,args.destination,args.reports)
