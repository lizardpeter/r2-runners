#!/usr/bin/env python3
"""Exact original Source 2 Vulkan VCS shader stages from a Steam VPK directory.

Only files genuinely indexed in game/csgo/shaders_vulkan_dir.vpk are requested.
No reconstructed shader bytecode, filename guesses, or substitute programs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import zlib
from pathlib import Path

from cs2_material_source_handoff import VPK_DIRECTORY_ARCHIVE, parse_vpk_index

SOURCE_FAMILIES = (
    "csgo_vertexlitgeneric",
    "csgo_lightmappedgeneric",
    "csgo_foliage",
    "csgo_effects",
    "csgo_complex",
    "csgo_static_overlay",
    "csgo_black_unlit",
    "sky",
)
FILE_PATTERN = re.compile(
    r"^shaders/vfx/("
    + "|".join(re.escape(family) for family in SOURCE_FAMILIES)
    + r")_vulkan_[0-9]+_(features|vs|ps|cs|gs|hs|ds)\.vcs$",
    re.IGNORECASE,
)
MAX_FILE_BYTES = 512 * 1024 * 1024


def matched_shader_files(index):
    return [entry for path, entry in sorted(index.entries.items())
            if FILE_PATTERN.fullmatch(path)]


def needed_segments(entries):
    return [f"game/csgo/shaders_vulkan_{index:03d}.vpk"
            for index in sorted({entry.archive_index for entry in entries
                                 if entry.archive_index != VPK_DIRECTORY_ARCHIVE})]


def shader_version_prefix(original):
    # VCS source bytes can begin with a retail Resource header or VCS2.
    if len(original) < 16:
        raise ValueError("truncated original VCS stage")
    if original[:4] == b"vcs2":
        return "vcs2"
    if struct.unpack_from("<H", original, 4)[0] == 12:
        return "source2-resource-v12"
    return "unrecognized-original-vcs-header"


def original_bytes(index, entry, depot_root):
    if entry.archive_index == VPK_DIRECTORY_ARCHIVE:
        path = index.path
        offset = index.data_start + entry.offset
    else:
        path = depot_root / f"game/csgo/shaders_vulkan_{entry.archive_index:03d}.vpk"
        offset = entry.offset
    if not path.is_file():
        raise FileNotFoundError(f"original compiled shader VPK segment not acquired: {path}")
    if entry.length > MAX_FILE_BYTES:
        raise ValueError(f"source VCS stage exceeds bounded reader budget: {entry.path}")
    with path.open("rb") as handle:
        handle.seek(offset)
        body = handle.read(entry.length)
    if len(body) != entry.length:
        raise ValueError(f"original shader stage truncated: {entry.path}")
    data = entry.preload + body
    crc = zlib.crc32(data) & 0xFFFFFFFF
    if crc != entry.crc32:
        raise ValueError(f"VPK CRC mismatch for {entry.path}: {crc:08x} != {entry.crc32:08x}")
    return data


def make_plan(index_path, output):
    index = parse_vpk_index(index_path)
    entries = matched_shader_files(index)
    seen = sorted(set(
        path.split("/")[2].split("_vulkan_")[0]
        for path in (entry.path for entry in entries)
    ))
    if not entries:
        raise ValueError("no original requested CS2 Vulkan shader family present in this VPK")
    missing_families = sorted(set(SOURCE_FAMILIES) - set(seen))
    stages = {family:[] for family in SOURCE_FAMILIES}
    for entry in entries:
        family = entry.path.split("/")[2].split("_vulkan_")[0]
        if family in stages:
            stages[family].append({
                "path": entry.path, "index": entry.archive_index,
                "length": entry.length, "crc32": f"{entry.crc32:08x}",
            })
    manifest = {
        "source": "Steam depot 730/2347770 game/csgo/shaders_vulkan_dir.vpk",
        "original_vpk_tree_bytes": index.tree_size,
        "source_material_families": list(SOURCE_FAMILIES),
        "indexed_shader_families": seen,
        "unindexed_shader_families": missing_families,
        "stage_files": len(entries),
        "physical_segments": needed_segments(entries),
        "stages": stages,
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/"source_shader_plan.json").write_text(
        json.dumps(manifest,indent=2)+"\n",encoding="utf-8"
    )
    (output/"shaders-segment-filelist.txt").write_text(
        "".join(path+"\n" for path in needed_segments(entries)),encoding="ascii"
    )
    print(json.dumps({
        "stage_files":len(entries),"indexed_shader_families":seen,
        "unindexed_shader_families":missing_families,
        "physical_segments":needed_segments(entries),
    },indent=2))


def extract(index_path,depot_root,output):
    index = parse_vpk_index(index_path)
    entries = matched_shader_files(index)
    if not entries:
        raise ValueError("original VCS stages not indexed in CS2 shader VPK")
    output.mkdir(parents=True,exist_ok=True)
    records = []
    for entry in entries:
        contents = original_bytes(index,entry,depot_root)
        destination=output/"cs2-base-resources"/entry.path
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(contents)
        records.append({
            "path":entry.path,
            "sha256":hashlib.sha256(contents).hexdigest(),
            "crc32":f"{entry.crc32:08x}",
            "size":len(contents),
            "archive_index":entry.archive_index,
            "source_offset":entry.offset,
            "header_style":shader_version_prefix(contents),
        })
    manifest={
        "source_depot":2347770,
        "source_archive":"game/csgo/shaders_vulkan_dir.vpk",
        "crc_verified":len(records),
        "original_bytes":sum(record["size"] for record in records),
        "files":records,
    }
    (output/"source_shader_manifest.json").write_text(
        json.dumps(manifest,indent=2)+"\n",encoding="utf-8"
    )
    print(json.dumps({
        "crc_verified":len(records),
        "original_bytes":manifest["original_bytes"],
        "header_styles":sorted(set(record["header_style"] for record in records)),
    },indent=2))


def test():
    assert FILE_PATTERN.fullmatch("shaders/vfx/csgo_complex_vulkan_50_ps.vcs")
    assert FILE_PATTERN.fullmatch("shaders/vfx/csgo_lightmappedgeneric_vulkan_50_vs.vcs")
    assert FILE_PATTERN.fullmatch("shaders/vfx/sky_vulkan_50_features.vcs")
    assert not FILE_PATTERN.fullmatch("shaders/vfx/other_shader_vulkan_50_ps.vcs")
    assert not FILE_PATTERN.fullmatch("../../shaders/vfx/sky_vulkan_50_ps.vcs")
    print("Source 2 original shader stage selector tests passed")


def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="cmd",required=True)
    for action in ("plan","extract"):
        p=sub.add_parser(action)
        p.add_argument("--index",required=True,type=Path)
        p.add_argument("--output",required=True,type=Path)
        if action=="extract":p.add_argument("--depot-root",required=True,type=Path)
    sub.add_parser("self-test")
    args=parser.parse_args()
    try:
        if args.cmd=="self-test":test()
        elif args.cmd=="plan":make_plan(args.index,args.output)
        else:extract(args.index,args.depot_root,args.output)
    except Exception as error:
        print(f"CS2 authentic Vulkan source handoff failed: {error}")
        return 1
    return 0

if __name__=="__main__":
    raise SystemExit(main())
