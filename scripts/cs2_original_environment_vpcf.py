#!/usr/bin/env python3
"""Acquire retail Source 2 compiled environmental particle graphs by EXACT VPK index.

Particle graph selection uses only authored compiled VPCF filenames actually
present in the authenticated base-game pak01_dir.vpk. This is NOT a map-specific
smokestack replay: Workshop-contained graphs must be audited independently.
"""
import argparse, hashlib, json, zlib
from pathlib import Path
from cs2_material_source_handoff import parse_vpk_index,VPK_DIRECTORY_ARCHIVE

ROOT="particles/"
# Broad environment animation families; names are selections over the INDEX,
# not invented candidate asset paths.
KEYWORDS=("smoke","smokestack","stack","steam","chimney","exhaust","furnace",
          "fire","flame","spark","flare","fog","dust","ambient","industrial")

def selected(index):
    return sorted([entry for path,entry in index.entries.items()
        if path.startswith(ROOT) and path.endswith(".vpcf_c") and
        any(key in path.lower() for key in KEYWORDS)], key=lambda e:e.path)

def archive_paths(entries):
    return [f"game/csgo/pak01_{n:03d}.vpk" for n in sorted({
        entry.archive_index for entry in entries
        if entry.archive_index!=VPK_DIRECTORY_ARCHIVE
    })]

def plan(index_path,output):
    index=parse_vpk_index(index_path)
    chosen=selected(index)
    if not chosen:
        raise ValueError("no source environmental VPCF graphs indexed in current CS2 depot")
    segments=archive_paths(chosen)
    output.mkdir(parents=True,exist_ok=True)
    (output/"original-particle-vpk-segments.txt").write_text(
        "".join(seg+"\n" for seg in segments),encoding="ascii"
    )
    (output/"original-particle-plan.json").write_text(json.dumps({
        "source":"Steam 730/2347770 game/csgo/pak01_dir.vpk",
        "selection":"Source-authored compiled VPCF resource path contains environmental token",
        "keywords":KEYWORDS,
        "source_entries":len(chosen),
        "physical_segments":segments,
        "vpcf_paths":[e.path for e in chosen],
    },indent=2)+"\n")
    print(json.dumps({"source_entries":len(chosen),
        "physical_segments":len(segments),
        "examples":[e.path for e in chosen[:20]]},indent=2))

def extract(index_path,source_root,output):
    index=parse_vpk_index(index_path)
    chosen=selected(index)
    if not chosen:
        raise ValueError("no original particle resources matched")
    records=[]
    for entry in chosen:
        if entry.archive_index==VPK_DIRECTORY_ARCHIVE:
            path,offset=index_path,index.data_start+entry.offset
        else:
            path=source_root/f"game/csgo/pak01_{entry.archive_index:03d}.vpk"
            offset=entry.offset
        if not path.is_file():
            raise FileNotFoundError(f"required original particle VPK segment missing: {path}")
        with path.open("rb") as stream:
            stream.seek(offset)
            body=stream.read(entry.length)
        if len(body)!=entry.length:
            raise ValueError(f"truncated original VPCF {entry.path}")
        blob=entry.preload+body
        crc=zlib.crc32(blob)&0xffffffff
        if crc!=entry.crc32:
            raise ValueError(f"original VPK CRC mismatch: {entry.path}")
        destination=output/"cs2-base-resources"/entry.path
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(blob)
        records.append({
            "source_path":entry.path,
            "bytes":len(blob),
            "sha256":hashlib.sha256(blob).hexdigest(),
            "source_vpk_crc32":f"{crc:08x}",
            "physical_segment":entry.archive_index,
        })
    output.mkdir(parents=True,exist_ok=True)
    (output/"original-environment-vpcf-manifest.json").write_text(
        json.dumps({"source":"Steam 730/2347770","crc_verified":len(records),
            "original_bytes":sum(r["bytes"] for r in records),"files":records},indent=2)+"\n"
    )
    print(json.dumps({"crc_verified":len(records),
        "original_bytes":sum(r["bytes"] for r in records)},indent=2))

def self_test():
    class Entry:
        def __init__(self,path,archive_index):self.path,self.archive_index=path,archive_index
    class Index:
        entries={
            "particles/environment/steam.vpcf_c":Entry("particles/environment/steam.vpcf_c",5),
            "particles/smokelight.vpcf_c":Entry("particles/smokelight.vpcf_c",11),
            "particles/vapor.vpcf_c":Entry("particles/vapor.vpcf_c",12),
            "particles/fog.vtex_c":Entry("particles/fog.vtex_c",13),
        }
    resources=selected(Index())
    assert [v.path for v in resources]==[
        "particles/environment/steam.vpcf_c","particles/smokelight.vpcf_c"]
    assert archive_paths(resources)==["game/csgo/pak01_005.vpk","game/csgo/pak01_011.vpk"]
    print("Original indexed environmental VPCF selector passed")

def main():
    args=argparse.ArgumentParser()
    modes=args.add_subparsers(dest="mode",required=True)
    modes.add_parser("self-test")
    for mode in ("plan","extract"):
        p=modes.add_parser(mode)
        p.add_argument("--index",type=Path,required=True)
        p.add_argument("--output",type=Path,required=True)
        if mode=="extract":p.add_argument("--source-root",type=Path,required=True)
    a=args.parse_args()
    try:
        if a.mode=="self-test":self_test()
        elif a.mode=="plan":plan(a.index,a.output)
        else:extract(a.index,a.source_root,a.output)
    except Exception as error:
        print(f"original environmental VPCF source closure failed: {error}")
        return 1
    return 0
if __name__=="__main__":
    raise SystemExit(main())
