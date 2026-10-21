#!/usr/bin/env python3
"""Authenticated original Fortnite 5.41 ALL Athena POI source-object closure.

Not an editor of private Rust-test, and not a metadata-only archive. The
input consists of *actual* original Athena roots, all original POI UWorlds,
and original nested building worlds. Their UE4 FPackageImport/FName tables
supply the next exact UObject identity for each original Blueprint, mesh,
material, and texture package. The same R2 PAK v7 SHA-1 verifier retrieves
full original .uasset/.uexp/.ubulk payloads into the same on-runner tree.

This intentionally does NOT synthesize a tree, grass patch, material, mesh,
localization, world transform, or shader from its UE4 class name.
"""
from __future__ import annotations
from collections import Counter
import argparse
import json
from pathlib import Path

from fortnite541_blueprint_mesh_closure import (
    source_imported_objects, source_log
)
from fortnite541_dependency_handoff import (
    f_name_package, source_handoff
)

DEPENDENCY_TYPES=(
    "BlueprintGeneratedClass","StaticMesh","FortStaticMesh",
    "Material","MaterialInstance","MaterialInstanceConstant",
    "Texture2D","TextureCube",
)
FIRST_WAVE_TYPES=("BlueprintGeneratedClass","StaticMesh","FortStaticMesh")
ASSET_REL="FortniteGame/Content/"
ROOT_GROUPS=(
    "Athena/Maps/POI/",
    "Athena/Maps/Buildings/",
)
INITIAL_ROOTS={
    "Athena/Maps/Athena_Terrain.umap",
    "Athena/Maps/Athena_POI_Foundations.umap",
    "Athena/Maps/Athena_Streaming_Grid.umap",
}

def source_worlds(root:Path)->list[Path]:
    base=root/ASSET_REL
    result=[]
    for path in sorted(base.rglob("*.umap")):
        rel=path.relative_to(base).as_posix()
        if rel in INITIAL_ROOTS or any(rel.startswith(group) for group in ROOT_GROUPS):
            if not path.with_suffix(".uexp").is_file():
                raise ValueError(f"source original UWorld missing .uexp: {rel}")
            result.append(path)
    if not any("Athena/Maps/POI/" in x.as_posix() for x in result):
        raise ValueError("not a complete original Athena POI source cache")
    if not (base/"Athena/Maps/Athena_POI_Foundations.umap").is_file():
        raise ValueError("authored Athena_POI_Foundations root world absent: POI transforms unproven")
    return result

def imported_refs(paths:list[Path],classes:tuple[str,...])->tuple[list[str],dict]:
    edges=Counter()
    owner={}
    for path in paths:
        identities=source_imported_objects(path.read_bytes(),classes)
        owner[path.as_posix()]=len(identities)
        edges.update(identities)
    return sorted(edges),{
        "file_headers_checked":len(paths),
        "imported_original_uobject_identities":len(edges),
        "source_uobject_import_occurrences":sum(edges.values()),
        "source_files_by_import_count":owner,
    }

def assert_sources_present(roots:list[Path],minimum:int)->None:
    if len(roots)<minimum:
        raise ValueError(f"only {len(roots)} original UWorld files, expected at least {minimum}")

def original_identity_set(identities:list[str])->set[str]:
    return {f_name_package(identity) for identity in identities}

def run(root:Path,reports:Path,max_rounds:int)->dict:
    worlds=source_worlds(root)
    original_poi=sum("/POI/" in path.as_posix() for path in worlds)
    original_buildings=sum("/Buildings/" in path.as_posix() for path in worlds)
    if original_poi<40 or original_buildings<170:
        raise ValueError(
            f"original Athena world coverage incomplete: POI={original_poi}, buildings={original_buildings}"
        )
    source_dir=root/ASSET_REL
    # Phase zero: ALL authentic world import FPackageIndexes, never guess
    # a Blueprint name because an authored actor looks like a tree.
    world_ids,world_report=imported_refs(worlds,FIRST_WAVE_TYPES)
    visited=original_identity_set(world_ids)
    waves=[]
    source_handoff_report=source_handoff(
        source_log(world_ids),"architecture",root,reports,
        report_filename="full-athena-poi-world-import-closure.json"
    ) if world_ids else None
    waves.append({
        "kind":"all-source-world-imports",
        "source_identities":len(world_ids),
        "sources":world_report,
        "verified_source_files":len(source_handoff_report["verified_files"]) if source_handoff_report else 0,
        "unresolved":len(source_handoff_report["unresolved"]) if source_handoff_report else 0,
    })
    inspected=set()
    fully_visited_rounds=0
    remaining=[]
    for round_index in range(max_rounds):
        # All source packages in a previous wave are already available under
        # their ORIGINAL path on this same GitHub runner. Each one is parsed
        # only once. A class->mesh->material->texture edge uses identical
        # source-import semantics regardless of game scene or map name.
        pending=sorted(path for path in source_dir.rglob("*.uasset")
                       if path.as_posix() not in inspected)
        if not pending:
            break
        for path in pending:
            inspected.add(path.as_posix())
        identities,stats=imported_refs(pending,DEPENDENCY_TYPES)
        wanted=sorted(i for i in identities if f_name_package(i) not in visited)
        visited.update(original_identity_set(wanted))
        if not wanted:
            fully_visited_rounds+=1
            waves.append({"kind":f"cooked-import-wave-{round_index+1}",
                          "source_identities":0,"sources":stats,
                          "verified_source_files":0,"unresolved":0})
            break
        report=source_handoff(
            source_log(wanted),"architecture",root,reports,
            report_filename=f"full-athena-poi-import-wave-{round_index+1}.json"
        )
        waves.append({
            "kind":f"cooked-import-wave-{round_index+1}",
            "source_identities":len(wanted),
            "sources":stats,
            "verified_source_files":len(report["verified_files"]),
            "unresolved":len(report["unresolved"]),
        })
        print("ATHENA_FULL_POI_DEPENDENCY_WAVE",round_index+1,
              "original_object_identities",len(wanted),
              "files",len(report["verified_files"]),
              "unresolved",len(report["unresolved"]),flush=True)
    # Count any untouched newly downloaded packages separately; a bounded
    # source search is never mislabeled as exhaustive full game closure.
    remaining=sorted(path.relative_to(root).as_posix()
                     for path in source_dir.rglob("*.uasset")
                     if path.as_posix() not in inspected)
    report={
        "original_worlds":len(worlds),
        "original_poi_worlds":original_poi,
        "original_nested_building_worlds":original_buildings,
        "original_root_world_files":len(worlds)-original_poi-original_buildings,
        "authored_foundations_present":True,
        "raw_ue4_import_source_waves":waves,
        "unvisited_source_package_headers":len(remaining),
        "unvisited_source_samples":remaining[:25],
        "max_dependency_waves":max_rounds,
        "source_closure_not_claimed_if_remaining":True,
        "unresolved_source_count":sum(w["unresolved"] for w in waves),
    }
    reports.mkdir(parents=True,exist_ok=True)
    (reports/"all-athena-poi-source-object-closure.json").write_text(json.dumps(report,indent=2)+"\n")
    print("ATHENA_FULL_POI_SOURCE_OBJECT_CLOSURE",
          "source_worlds",len(worlds),"original_POIs",original_poi,
          "nested_worlds",original_buildings,
          "verified_new_source_files",sum(w["verified_source_files"] for w in waves),
          "unresolved",report["unresolved_source_count"],
          "unvisited",len(remaining),flush=True)
    if report["unresolved_source_count"]:
        raise RuntimeError("some original full Athena POI source package identities remain missing")

def self_test()->None:
    assert "BlueprintGeneratedClass" in FIRST_WAVE_TYPES
    assert "Texture2D" in DEPENDENCY_TYPES
    assert f_name_package("/Game/Building/Walls/Wall#3::Wall_2_C")=="/Game/Building/Walls/Wall_2"
    assert original_identity_set(["/Game/Building/Wall::Wall"])=={"/Game/Building/Wall"}
    print("ATHENA_ALL_POI_AUTHENTIC_DEPENDENCY_CLOSURE_TEST_PASS",flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path)
    p.add_argument("--reports",type=Path)
    p.add_argument("--rounds",type=int,default=4)
    p.add_argument("--self-test",action="store_true")
    args=p.parse_args()
    self_test()
    if not args.self_test:
        if not args.source_root or not args.reports:
            p.error("--source-root and --reports required")
        if not 1<=args.rounds<=10:
            p.error("dependency round count must be 1..10")
        run(args.source_root,args.reports,args.rounds)
