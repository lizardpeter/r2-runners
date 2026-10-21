#!/usr/bin/env python3
"""Download BO1 source assets to runner-local scratch, probe actual T5 headers.

Strictly emits JSON facts about source binaries, never republishes binaries.
An R2 inventory generated from the Cloudflare account anchors object identity.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import zipfile
import zlib
from urllib.parse import quote

from r2_download import download

MAX_ZONE_BYTES = 1024 * 1024 * 1024
FF_MAGIC = {b"IWffu100", b"IWff0100"}
ROOT_MAP_NAMES = {"nuketown": "mp_nuked.ff", "firingrange": "mp_firingrange.ff"}
MAX_FILES = 128


def read_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ValueError(f"T5 buffer ends before 32-bit field at 0x{offset:X}")
    return struct.unpack_from("<I", data, offset)[0]


def check_pointer(raw: int, block_sizes: list[int]) -> None:
    if raw in (0, 0xFFFFFFFF, 0xFFFFFFFE):
        return
    pointer = raw - 1
    block, offset = pointer >> 29, pointer & 0x1FFFFFFF
    if block >= len(block_sizes) or offset >= block_sizes[block]:
        raise ValueError(f"T5 XFile pointer 0x{raw:08x} exceeds block {block}")


def extract_t5_zone(data: bytes) -> bytes:
    if len(data) < 14 or data[:8] not in FF_MAGIC:
        raise ValueError("Original file does not have a supported T5 PC FastFile magic")
    version = read_u32(data, 8)
    if version != 0x1D9:
        raise ValueError(f"Not BO1 PC FastFile version 0x1D9 (found 0x{version:x})")
    if data[:8] == b"IWff0100":
        raise ValueError("Signed BO1 FastFile requires authenticated signed-block framing")
    head = data[12:14]
    if head[0] & 15 != 8 or head[0] >> 4 > 7 or ((head[0] << 8) + head[1]) % 31:
        raise ValueError("BO1 FastFile is not the verified zlib-at-offset-12 variant")
    d = zlib.decompressobj()
    output = bytearray()
    for start in range(12, len(data), 1024 * 1024):
        output.extend(d.decompress(data[start:start + 1024 * 1024],
                                   MAX_ZONE_BYTES + 1 - len(output)))
        if len(output) > MAX_ZONE_BYTES:
            raise ValueError("Expanded T5 zone exceeds 1 GiB")
    output.extend(d.flush(MAX_ZONE_BYTES + 1 - len(output)))
    if not d.eof or len(output) < 52:
        raise ValueError("BO1 zlib payload ended prematurely or zone header is missing")
    if len(output) > MAX_ZONE_BYTES:
        raise ValueError("Expanded T5 zone exceeds 1 GiB")
    return bytes(output)


def probe_ff(data: bytes) -> dict:
    magic = data[:8].decode("ascii", "replace")
    version = read_u32(data, 8)
    result = {"magic": magic, "version": version,
              "signed": magic == "IWff0100"}
    zone = extract_t5_zone(data)
    block_sizes = [read_u32(zone, 8 + i * 4) for i in range(7)]
    script_count = read_u32(zone, 36)
    asset_count = read_u32(zone, 44)
    script_ptr = read_u32(zone, 40)
    asset_ptr = read_u32(zone, 48)
    if script_count > 2_000_000 or asset_count > 2_000_000:
        raise ValueError("T5 source asset/script count out of bounds")
    result.update({
        "expanded_bytes": len(zone),
        "declared_data_bytes": read_u32(zone, 0),
        "external_bytes": read_u32(zone, 4),
        "xfile_block_sizes": block_sizes,
        "script_count": script_count,
        "asset_count": asset_count,
        "asset_table_pointer": asset_ptr,
    })
    cursor = 52
    if script_count:
        if script_ptr != 0xFFFFFFFF:
            result["asset_table_status"] = "script table needs packed-pointer replay"
            return result
        limit = cursor + 4 * script_count
        if limit > len(zone):
            raise ValueError("T5 script pointer table is truncated")
        ptrs = [read_u32(zone, at) for at in range(cursor, limit, 4)]
        cursor = limit
        for pointer in ptrs:
            if pointer == 0:
                continue
            if pointer != 0xFFFFFFFF:
                result["asset_table_status"] = "script string requires packed-pointer replay"
                return result
            end = zone.find(b"\0", cursor, min(cursor + 1_048_577, len(zone)))
            if end < 0:
                raise ValueError("BO1 original script string is unterminated")
            zone[cursor:end].decode("utf-8", "strict")
            cursor = end + 1
    elif script_ptr:
        raise ValueError("BO1 source declares no scripts but has non-null script pointer")
    if asset_count and asset_ptr != 0xFFFFFFFF:
        result["asset_table_status"] = "asset table needs packed-pointer replay"
        return result
    if cursor + asset_count * 8 > len(zone):
        raise ValueError("T5 original serialized XAsset list truncated")
    categories = Counter()
    for index in range(asset_count):
        at = cursor + index * 8
        asset_type = read_u32(zone, at)
        if asset_type > 256:
            raise ValueError(f"T5 serialized XAsset {index} invalid type {asset_type}")
        check_pointer(read_u32(zone, at + 4), block_sizes)
        categories[str(asset_type)] += 1
    result.update({"asset_table_status": "decoded_serialized",
                   "asset_table_offset": cursor,
                   "asset_types": dict(sorted(categories.items(), key=lambda x: int(x[0])))})
    return result


def probe_iwd(path: Path) -> dict:
    # T5 server distributions contain archives named .iwd that are not ZIPs.
    # Preserve their original header bytes as source evidence; do not treat
    # them as IWI containers or claim to have decoded textures from them.
    with path.open("rb") as stream:
        prefix = stream.read(32)
    if not zipfile.is_zipfile(path):
        return {"container_status": "unrecognized_not_zip",
                "signature_hex": prefix.hex(),
                "iwi_members": None,
                "iwi_uncompressed_bytes": None,
                "source_bytes_preserved": True}
    with zipfile.ZipFile(path) as z:
        if len(z.infolist()) > 250_000:
            raise ValueError("IWD central directory contains too many entries")
        files = [x for x in z.infolist() if not x.is_dir()]
        names = [x.filename.lower() for x in files]
        images = [x for x in files if x.filename.lower().endswith(".iwi")]
        if len(names) != len(set(names)):
            raise ValueError("IWD has duplicate logical member names")
        for x in files:
            if x.filename.startswith("/") or ".." in x.filename.replace("\\", "/").split("/"):
                raise ValueError("Unsafe IWD member path")
        return {"container_status": "zip", "members": len(files), "iwi_members": len(images),
                "iwi_uncompressed_bytes": sum(x.file_size for x in images),
                "iwi_sample_names": [x.filename for x in images[:8]]}


def select_assets(manifest: dict, preset: str) -> list[dict]:
    lookup = {f["path"]: f for f in manifest["files"]}
    required = {"zone/Common/common_mp.ff", "zone/Common/patch_mp.ff"}
    if preset == "all_multiplayer":
        required.update(p for p in lookup if
                        p.startswith("zone/Common/mp_") and p.endswith(".ff"))
    else:
        selected = ("nuketown", "firingrange") if preset == "both" else (preset,)
        required.update("zone/Common/" + ROOT_MAP_NAMES[name] for name in selected)
    # Check the installed original texture archives too; they are small,
    # independently authenticated R2 records and often source dependencies.
    required.update(p for p in lookup if p.startswith("main/") and p.endswith(".iwd"))
    missing = sorted(required - lookup.keys())
    if missing:
        raise ValueError(f"Manifest lacks original files: {missing}")
    if len(required) > MAX_FILES:
        raise ValueError("Selected original source file count exceeds bound")
    return [lookup[name] for name in sorted(required)]


def source_md5(path: Path) -> str:
    h = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(manifest_path: Path, out: Path, preset: str) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("bucket") != "houseofkublai" or manifest.get("origin") != "https://r2.houseofkublai.com":
        raise ValueError("Manifest is not the expected authenticated R2 inventory")
    prefix = manifest["key_prefix"]
    if not prefix.startswith("bo1/") or ".." in prefix or "\\" in prefix:
        raise ValueError("Untrusted R2 inventory prefix")
    selected = select_assets(manifest, preset)
    root = out / "original-bo1"
    report_dir = out / "report"
    root.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {"preset": preset, "bucket": manifest["bucket"],
              "files": [], "all_verified": False,
              "source_asset_root": "runner temporary directory, not uploaded"}
    errors = []
    for spec in selected:
        rel = spec["path"]
        if not rel.startswith(("zone/Common/", "main/")) or ".." in rel or "\\" in rel:
            raise ValueError(f"Manifest contains unsafe relative path {rel!r}")
        dest = root.joinpath(*rel.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        key = prefix + rel
        url = manifest["origin"] + "/" + quote(key, safe="/")
        item = {"path": rel, "expected_bytes": spec["bytes"],
                "r2_etag": spec["etag"]}
        try:
            size, sha256, _ = download(url, dest, max_bytes=max(spec["bytes"], 1))
            item["bytes"] = size
            item["sha256"] = sha256
            if size != spec["bytes"]:
                raise ValueError(f"Size {size} does not match R2 inventory {spec['bytes']}")
            item["size_verified"] = True
            # ETags are usually MD5 for single-part R2 objects but this is
            # not universally guaranteed. Record whether the values match,
            # not a false unconditional assertion about multipart objects.
            item["md5_equals_r2_etag"] = (bool(re.fullmatch(r"[0-9a-f]{32}", spec["etag"])) and
                                          source_md5(dest) == spec["etag"])
            if rel.endswith(".ff"):
                item["t5_fastfile"] = probe_ff(dest.read_bytes())
            elif rel.endswith(".iwd"):
                item["iwd"] = probe_iwd(dest)
            item["status"] = "ok"
        except Exception as exc:
            item["status"] = "error"
            item["error"] = str(exc)
            errors.append(f"{rel}: {exc}")
        report["files"].append(item)
        (report_dir / "bo1-real-source-report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["all_verified"] = not errors
    report["downloaded_file_count"] = len(selected)
    report["successful_files"] = len(selected) - len(errors)
    report["source_xassets"] = sum(f.get("t5_fastfile", {}).get("asset_count", 0)
                                    for f in report["files"])
    (report_dir / "bo1-real-source-report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = (
        f"## BO1 original R2 source audit\n\n"
        f"- Preset: {preset}\n"
        f"- Original files: {len(selected)}\n"
        f"- Source-verified: {len(selected)-len(errors)}\n"
        f"- Source-declared XAsset records: {report['source_xassets']}\n"
        f"- Binary assets: runner-local only; JSON report is the only artifact\n"
    )
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary)
    print(summary)
    for item in report["files"]:
        if item["status"] != "ok":
            print(f"ERROR {item['path']}: {item.get('error')}", file=sys.stderr)
        elif "t5_fastfile" in item:
            h = item["t5_fastfile"]
            print(f"T5 {item['path']}: {h['asset_count']} assets, "
                  f"{h['expanded_bytes']} zone bytes, {h.get('asset_table_status')}")
    if errors:
        raise RuntimeError(f"BO1 original source probe failed for {len(errors)} files")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("manifests/bo1-server.json"))
    parser.add_argument("--preset", choices=["nuketown", "firingrange", "both", "all_multiplayer"],
                        default="both")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest, args.output_dir, args.preset)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"BO1 real-source probe: {error}", file=sys.stderr)
        sys.exit(1)
