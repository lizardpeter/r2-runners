#!/usr/bin/env python3
"""Actual original compiled VTEX dependencies of CRC-verified smokestack VPCFs.

Do not substitute generic noise or a static quad. These paths were read from
the original Source2 m_vecTexturesInput[] for ambient_smokestack(.vpcf_c),
ambient_smokestack_noise and italy_smokestack_softeners.
"""
import argparse,hashlib,json
from pathlib import Path
from cs2_material_source_handoff import (
    parse_vpk_index,resolve_targets_with_missing,segment_names,_entry_bytes
)

TARGETS=[
 "materials/particle/vistasmokev1/vistasmokev1_emods.vtex_c",
 "materials/particle/smoke1/smoke1.vtex_c",
 "materials/particle/particle_smokegrenade.vtex_c"
]
def plan(index_path,output):
    index=parse_vpk_index(index_path)
    entries,missing=resolve_targets_with_missing(index,TARGETS)
    if not entries:raise ValueError("no source VPCF sprite VTEX in this retail VPK")
    segments=segment_names(entries)
    output.mkdir(parents=True,exist_ok=True)
    (output/"smoke-vtex-segments.txt").write_text("".join(s+"\n" for s in segments))
    (output/"smoke-vtex-plan.json").write_text(json.dumps({
        "source":"Steam depot 730/2347770 original VPCF sprite slots",
        "selected":TARGETS,
        "original_indexed":[e.path for e in entries],
        "unresolved_original_source":missing,
        "physical_segments":segments
    },indent=2)+"\n")
    print(json.dumps({"indexed":len(entries),"missing":missing,"segments":segments},indent=2))
def extract(index_path,source_root,output):
    index=parse_vpk_index(index_path)
    entries,missing=resolve_targets_with_missing(index,TARGETS)
    results=[]
    for entry in entries:
        blob=_entry_bytes(index,entry,source_root)
        path=output/"cs2-base-resources"/entry.path
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(blob)
        results.append({
            "path":entry.path,
            "sha256":hashlib.sha256(blob).hexdigest(),
            "source_crc32":f"{entry.crc32:08x}",
            "source_bytes":len(blob),
            "index":entry.archive_index
        })
    if not entries:raise ValueError("no actual original source VTEX extracted")
    output.mkdir(parents=True,exist_ok=True)
    (output/"smoke-original-vtex-manifest.json").write_text(json.dumps({
        "crc_verified":len(results),"unresolved_paths":missing,"files":results
    },indent=2)+"\n")
    print(json.dumps({"verified":len(results),"missing":missing},indent=2))
def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest="mode",required=True)
    for mode in ("plan","extract"):
        q=sub.add_parser(mode)
        q.add_argument("--index",type=Path,required=True)
        q.add_argument("--output",type=Path,required=True)
        if mode=="extract":q.add_argument("--source-root",type=Path,required=True)
    args=p.parse_args()
    try:
        if args.mode=="plan":plan(args.index,args.output)
        else:extract(args.index,args.source_root,args.output)
    except Exception as err:
        print(f"original Source2 sprite VTEX source handoff failed: {err}")
        return 1
    return 0
if __name__=="__main__":raise SystemExit(main())
