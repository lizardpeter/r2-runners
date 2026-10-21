#!/usr/bin/env python3
"""Recover the exact UMaterialInterface and Texture objects imported by
original Fortnite 5.41 architecture, exclusively from authenticated PAKs.

The discovery begins with original retail UStaticMesh cooked import tables.
A second pass walks recovered material packages for their authentic imported
material parents and source texture references. It never invents textures or
assumes a missing PAK object exists. Each original byte and SHA1 is retained.
"""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import argparse
import json

from fortnite541_blueprint_mesh_closure import source_imported_objects, source_log
from fortnite541_dependency_handoff import source_handoff

MATERIAL = ("MaterialInstanceConstant", "Material", "MaterialInstance",
            "MaterialInstanceDynamic")
TEXTURE = ("Texture2D", "TextureCube")
DEPENDENCY = MATERIAL + TEXTURE

def inspect_packages(root: Path, skip_blueprints: bool, classes: tuple[str, ...]) -> tuple[list[str],dict]:
    source_root = root / "FortniteGame" / "Content"
    files = sorted(source_root.rglob("*.uasset"))
    inspected = 0
    source_imports: Counter[str] = Counter()
    owner_paths: dict[str,list[str]] = {}
    for path in files:
        local = path.relative_to(source_root).as_posix()
        if skip_blueprints and local.startswith("Building/ActorBlueprints/"):
            continue
        # Exclude a source file's own package from import extraction only if
        # the package has no foreign source UObject refs (no invented self parent).
        selected = source_imported_objects(path.read_bytes(), classes)
        inspected += 1
        if selected:
            owner_paths[local] = selected
            source_imports.update(selected)
    return sorted(source_imports), {
        "cooked_package_headers_parsed": inspected,
        "imported_original_uobject_identities": len(source_imports),
        "original_import_edges": sum(source_imports.values()),
        "source_owners": owner_paths
    }

def has_verified_pair(root: Path, source: str) -> bool:
    package=source.split("::",1)[0]
    if not package.startswith("/Game/"):
        return False
    relative = package[6:]
    base=root/"FortniteGame"/"Content"/relative
    return base.with_suffix(".uasset").is_file() and base.with_suffix(".uexp").is_file()

def run(root:Path, reports:Path) -> dict:
    # First pass: each verified source UStaticMesh's authentic material and
    # texture import. Important: these are REFERENCES, not yet GPU shaders.
    initial, inventory = inspect_packages(root,True,DEPENDENCY)
    first=source_handoff(
        source_log(initial),"architecture",root,reports,
        report_filename="original-architecture-materials-stage1.json"
    )
    # Second pass: surviving original MIC/UMaterial source import tables
    # contain actual ancestor materials and texture identities. The first
    # pass's files are already available on the same runner (no deletion).
    all_known=set(initial)
    second_sources, second_inventory = inspect_packages(root,True,DEPENDENCY)
    second_missing=sorted(x for x in second_sources if x not in all_known)
    second=None
    if second_missing:
        second=source_handoff(
            source_log(second_missing),"architecture",root,reports,
            report_filename="original-architecture-materials-stage2.json"
        )
    # One more layer closes parent and texture imports of the second set.
    all_known.update(second_missing)
    third_sources, third_inventory=inspect_packages(root,True,DEPENDENCY)
    third_missing=sorted(x for x in third_sources if x not in all_known)
    third=None
    if third_missing:
        third=source_handoff(
            source_log(third_missing),"architecture",root,reports,
            report_filename="original-architecture-materials-stage3.json"
        )
    final={
        "original_source_only":True,
        "authentic_source_object_references":len(set(initial)|set(second_missing)|set(third_missing)),
        "first_stage":inventory,
        "second_stage":second_inventory,
        "third_stage":third_inventory,
        "verified_file_counts":[len(d["verified_files"]) if d else 0 for d in (first,second,third)],
        "unresolved_source_counts":[len(d["unresolved"]) if d else 0 for d in (first,second,third)],
        "unresolved_source_samples":[d["unresolved"][:15] if d else [] for d in (first,second,third)],
    }
    reports.mkdir(parents=True,exist_ok=True)
    (reports/"original-material-texture-source-closure.json").write_text(json.dumps(final,indent=2)+"\n")
    print("FORTNITE541_RETAIL_MATERIAL_TEXTURE_SOURCE_CLOSURE",
          "identities",final["authentic_source_object_references"],
          "stage_source_files",final["verified_file_counts"],
          "unresolved",final["unresolved_source_counts"],flush=True)
    return final

if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-root",type=Path,required=True)
    ap.add_argument("--report-dir",type=Path,required=True)
    a=ap.parse_args()
    run(a.source_root,a.report_dir)
