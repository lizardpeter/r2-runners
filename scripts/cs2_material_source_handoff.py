#!/usr/bin/env python3
"""Fetch exact CS2 VMAT-referenced VTEX entries from the anonymous base VPK.

This is a narrow source-handoff tool: it downloads no whole game archive, resolves
only the explicitly enumerated missing texture paths through the original VPK
directory index, and verifies each extracted entry against the VPK CRC32.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import tempfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

VPK_MAGIC = 0x55AA1234
VPK_DIRECTORY_ARCHIVE = 0x7FFF
VPK_MAX_TREE_BYTES = 64 * 1024 * 1024
VPK_MAX_ENTRIES = 2_000_000
VPK_MAX_STRING_BYTES = 4096

# These are the exact unresolved VMAT texture references from the current
# 275-material / 726-texture original-source audit. Keep the compiled paths.
TARGETS = (
    "materials/default/default_ao_tga_559f1ac6.vtex_c",
    "materials/default/default_normal_tga_7be61377.vtex_c",
    "materials/models/de_overpass/industrial/concrete_block/ground_1_detail_psd_c1731146.vtex_c",
)


@dataclass(frozen=True)
class VpkEntry:
    path: str
    crc32: int
    preload: bytes
    archive_index: int
    offset: int
    length: int


@dataclass(frozen=True)
class VpkIndex:
    path: Path
    version: int
    tree_size: int
    data_start: int
    entries: dict[str, VpkEntry]


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated VPK uint16")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated VPK uint32")
    return struct.unpack_from("<I", data, offset)[0]


def _cstring(data: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(data):
        raise ValueError("VPK tree string starts outside the tree")
    end = data.find(b"\0", offset, min(len(data), offset + VPK_MAX_STRING_BYTES + 1))
    if end < 0:
        raise ValueError("unterminated or oversized VPK tree string")
    try:
        value = data[offset:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8 in VPK tree") from exc
    return value, end + 1


def _safe_path(path: str) -> bool:
    return (
        bool(path)
        and not path.startswith("/")
        and "\\" not in path
        and ":" not in path
        and all(part not in ("", ".", "..") for part in path.split("/"))
    )


def parse_vpk_index(path: Path) -> VpkIndex:
    data = path.read_bytes()
    if len(data) < 12 or _u32(data, 0) != VPK_MAGIC:
        raise ValueError(f"{path} is not a Valve VPK directory")
    version = _u32(data, 4)
    if version == 1:
        header_size = 12
    elif version == 2:
        if len(data) < 28:
            raise ValueError("truncated VPK v2 header")
        header_size = 28
    else:
        raise ValueError(f"unsupported VPK version {version}")
    tree_size = _u32(data, 8)
    if tree_size > VPK_MAX_TREE_BYTES:
        raise ValueError(f"VPK tree exceeds {VPK_MAX_TREE_BYTES} bytes")
    tree_end = header_size + tree_size
    if tree_end > len(data):
        raise ValueError("VPK tree extends past the directory file")
    tree = data[header_size:tree_end]
    entries: dict[str, VpkEntry] = {}
    cursor = 0

    while True:
        extension, cursor = _cstring(tree, cursor)
        if extension == "":
            break
        if "/" in extension or "\\" in extension or ":" in extension:
            raise ValueError(f"unsafe VPK extension {extension!r}")
        while True:
            folder, cursor = _cstring(tree, cursor)
            if folder == "":
                break
            if folder != " " and not _safe_path(folder):
                raise ValueError(f"unsafe VPK folder {folder!r}")
            while True:
                stem, cursor = _cstring(tree, cursor)
                if stem == "":
                    break
                if not _safe_path(stem) or "/" in stem:
                    raise ValueError(f"unsafe VPK file stem {stem!r}")
                if cursor + 18 > len(tree):
                    raise ValueError("truncated VPK entry metadata")
                crc32, preload_size, archive_index, offset, length, sentinel = struct.unpack_from(
                    "<IHHIIH", tree, cursor
                )
                if sentinel != 0xFFFF:
                    raise ValueError("invalid VPK entry sentinel")
                cursor += 18
                preload_end = cursor + preload_size
                if preload_end > len(tree):
                    raise ValueError("truncated VPK preload bytes")
                preload = tree[cursor:preload_end]
                cursor = preload_end
                path_parts = [] if folder == " " else folder.split("/")
                path_parts.append(stem)
                full_path = "/".join(path_parts)
                if extension:
                    full_path += "." + extension
                if not _safe_path(full_path):
                    raise ValueError(f"unsafe resolved VPK path {full_path!r}")
                key = full_path.casefold()
                if key in entries:
                    raise ValueError(f"duplicate VPK path (case-insensitive): {full_path}")
                entries[key] = VpkEntry(
                    path=full_path,
                    crc32=crc32,
                    preload=preload,
                    archive_index=archive_index,
                    offset=offset,
                    length=length,
                )
                if len(entries) > VPK_MAX_ENTRIES:
                    raise ValueError("VPK entry count exceeds safety limit")
    if cursor != len(tree):
        raise ValueError(f"VPK tree has {len(tree) - cursor} unparsed trailing bytes")
    return VpkIndex(path, version, tree_size, tree_end, entries)


def resolve_targets(index: VpkIndex, targets: Iterable[str] = TARGETS) -> list[VpkEntry]:
    result: list[VpkEntry] = []
    for target in targets:
        if not _safe_path(target):
            raise ValueError(f"unsafe requested target {target!r}")
        entry = index.entries.get(target.casefold())
        if entry is None:
            raise ValueError(f"exact original VMAT texture not found in pak01_dir.vpk: {target}")
        result.append(entry)
    return result


def segment_names(entries: Iterable[VpkEntry]) -> list[str]:
    indices = sorted({
        entry.archive_index
        for entry in entries
        if entry.archive_index != VPK_DIRECTORY_ARCHIVE
    })
    return [f"game/csgo/pak01_{index:03d}.vpk" for index in indices]


def _entry_bytes(index: VpkIndex, entry: VpkEntry, source_root: Path) -> bytes:
    if entry.archive_index == VPK_DIRECTORY_ARCHIVE:
        source = index.path
        start = index.data_start + entry.offset
    else:
        source = source_root / "game" / "csgo" / f"pak01_{entry.archive_index:03d}.vpk"
        if not source.is_file():
            raise FileNotFoundError(f"required original VPK segment is missing: {source}")
        start = entry.offset
    with source.open("rb") as stream:
        stream.seek(start)
        data = stream.read(entry.length)
    if len(data) != entry.length:
        raise ValueError(f"truncated source entry {entry.path}: {len(data)} of {entry.length} bytes")
    full = entry.preload + data
    actual_crc = zlib.crc32(full) & 0xFFFFFFFF
    if actual_crc != entry.crc32:
        raise ValueError(
            f"original VPK CRC mismatch for {entry.path}: "
            f"expected {entry.crc32:08x}, got {actual_crc:08x}"
        )
    return full


def plan(index_path: Path, filelist_path: Path, report_path: Path) -> None:
    index = parse_vpk_index(index_path)
    entries = resolve_targets(index)
    segments = segment_names(entries)
    filelist_path.parent.mkdir(parents=True, exist_ok=True)
    filelist_path.write_text("".join(name + "\n" for name in segments), encoding="ascii")
    report = {
        "source_app": 730,
        "source_depot": 2347770,
        "index": str(index_path),
        "vpk_version": index.version,
        "tree_bytes": index.tree_size,
        "target_count": len(entries),
        "segment_files": segments,
        "targets": [
            {
                "path": e.path,
                "crc32": f"{e.crc32:08x}",
                "archive_index": e.archive_index,
                "offset": e.offset,
                "length": e.length,
                "preload_bytes": len(e.preload),
            }
            for e in entries
        ],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"target_count": len(entries), "segment_files": segments}, indent=2))


def extract(index_path: Path, source_root: Path, output_dir: Path, report_path: Path) -> None:
    index = parse_vpk_index(index_path)
    entries = resolve_targets(index)
    manifest = {
        "source_app": 730,
        "source_depot": 2347770,
        "vpk_index_version": index.version,
        "vpk_tree_bytes": index.tree_size,
        "verification": "each extracted original entry must pass its VPK CRC32",
        "files": [],
    }
    for entry in entries:
        blob = _entry_bytes(index, entry, source_root)
        target = output_dir / "cs2-base-resources" / Path(entry.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        manifest["files"].append({
            "path": entry.path,
            "output": str(target.relative_to(output_dir)).replace("\\", "/"),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "crc32": f"{zlib.crc32(blob) & 0xFFFFFFFF:08x}",
            "source_vpk_crc32": f"{entry.crc32:08x}",
            "archive_index": entry.archive_index,
            "offset": entry.offset,
            "stored_length": entry.length,
            "preload_bytes": len(entry.preload),
            "output_bytes": len(blob),
        })
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verified_files": len(manifest["files"]), "report": str(report_path)}, indent=2))


def _encode_cstring(value: str) -> bytes:
    return value.encode("utf-8") + b"\0"


def self_test() -> None:
    # Tiny synthetic VPK v2 with one segmented and one directory-inline entry.
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        segment_bytes = b"hello"
        inline_bytes = b"inline"
        segment_preload = b"pre"
        tree = bytearray()
        tree += _encode_cstring("vtex_c")
        tree += _encode_cstring("materials/default")
        for stem, preload, archive_index, offset, stored in (
            ("segmented", segment_preload, 0, 0, segment_bytes),
            ("inline", b"", VPK_DIRECTORY_ARCHIVE, 0, inline_bytes),
        ):
            full = preload + stored
            tree += _encode_cstring(stem)
            tree += struct.pack("<IHHIIH", zlib.crc32(full) & 0xFFFFFFFF,
                                len(preload), archive_index, offset, len(stored), 0xFFFF)
            tree += preload
        tree += _encode_cstring("")  # end filenames
        tree += _encode_cstring("")  # end folders
        tree += _encode_cstring("")  # end extensions
        header = struct.pack("<IIIIIII", VPK_MAGIC, 2, len(tree), len(inline_bytes), 0, 0, 0)
        index_path = root / "pak01_dir.vpk"
        index_path.write_bytes(header + tree + inline_bytes)
        (root / "game" / "csgo").mkdir(parents=True)
        (root / "game" / "csgo" / "pak01_000.vpk").write_bytes(segment_bytes)
        index = parse_vpk_index(index_path)
        segmented = index.entries["materials/default/segmented.vtex_c"]
        inline = index.entries["materials/default/inline.vtex_c"]
        assert _entry_bytes(index, segmented, root) == segment_preload + segment_bytes
        assert _entry_bytes(index, inline, root) == inline_bytes
    print("CS2 VPK source handoff self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    plan_parser = sub.add_parser("plan", help="resolve exact target resources to original VPK segments")
    plan_parser.add_argument("--vpk-index", type=Path, required=True)
    plan_parser.add_argument("--filelist", type=Path, required=True)
    plan_parser.add_argument("--report", type=Path, required=True)
    extract_parser = sub.add_parser("extract", help="extract and CRC-verify exact original source resources")
    extract_parser.add_argument("--vpk-index", type=Path, required=True)
    extract_parser.add_argument("--source-root", type=Path, required=True)
    extract_parser.add_argument("--output-dir", type=Path, required=True)
    extract_parser.add_argument("--report", type=Path, required=True)
    sub.add_parser("self-test", help="test VPK parsing, segment addressing, preload, and CRC validation")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            plan(args.vpk_index, args.filelist, args.report)
        elif args.command == "extract":
            extract(args.vpk_index, args.source_root, args.output_dir, args.report)
        else:
            self_test()
    except Exception as exc:
        print(f"CS2 source handoff failed: {exc}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
