#!/usr/bin/env python3
"""Bounded first-contact inspection of original IW5 game bytes in the owner's R2 ZIP.

Reads the ZIP64 central directory using HTTP byte ranges. Source .ff/.iwd files
are inspected only in ephemeral runner storage. JSON reports contain metadata,
counts, hashes and short hex signatures, never copyrighted source payloads.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from urllib.request import Request, urlopen
import zipfile
import zlib

from bo1_full_game_range import HttpRangeObject

SOURCE_URL = "https://r2.houseofkublai.com/downloads/games/pluto_iw5_full_game.zip"
MAX_SINGLE_BYTES = 450 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_IWD_BYTES = 110 * 1024 * 1024
CHUNK = 1 << 20
SIGNATURE_BYTES = 8192
MAX_ZLIB_OUTPUT = 65536


def remote_size(url: str) -> int:
    request = Request(url, method="HEAD", headers={"Accept-Encoding": "identity"})
    try:
        with urlopen(request, timeout=60) as response:
            if response.status == 200:
                n = int(response.headers.get("Content-Length", "0"))
                if n > 0:
                    return n
    except Exception:
        pass
    # Server might reject HEAD; a one-byte ranged GET still establishes size.
    request = Request(url, headers={"Range": "bytes=0-0", "Accept-Encoding": "identity"})
    with urlopen(request, timeout=60) as response:
        if response.status != 206:
            raise RuntimeError("R2 does not support bounded byte-range requests")
        value = response.headers.get("Content-Range", "")
        m = re.fullmatch(r"bytes 0-0/([0-9]+)", value)
        if not m:
            raise RuntimeError(f"Unrecognized R2 Content-Range {value!r}")
        if len(response.read(2)) != 1:
            raise RuntimeError("R2 one-byte probe returned an unexpected length")
        return int(m.group(1))


def safe_member_name(path: str) -> str | None:
    value = path.replace("\\", "/").strip("/")
    parts = PurePosixPath(value).parts
    if not parts or any(p in ("..", ".", "") for p in parts):
        return None
    if re.match(r"^[A-Za-z]:", value):
        return None
    return "/".join(parts)


def classify(path: str) -> str:
    p = path.lower()
    if p.endswith(".ff"):
        return "fastfile"
    if p.endswith(".iwd"):
        return "iwd"
    if p.endswith(".iwi"):
        return "image"
    if p.endswith(".bsp"):
        return "bsp"
    if p.endswith(".bik"):
        return "video"
    if p.endswith((".exe", ".dll")):
        return "executable"
    if p.endswith((".csv", ".gsc", ".cfg", ".txt")):
        return "text"
    return "other"


def zlib_candidates(prefix: bytes) -> list[dict]:
    matches = []
    for offset in range(0, min(len(prefix) - 2, 4096)):
        cmf, flg = prefix[offset], prefix[offset + 1]
        if cmf & 15 != 8 or (cmf >> 4) > 7 or (cmf * 256 + flg) % 31 or (flg & 0x20):
            continue
        try:
            decoder = zlib.decompressobj()
            sample = decoder.decompress(prefix[offset:], MAX_ZLIB_OUTPUT)
            if len(sample) < 24:
                continue
            matches.append({
                "offset": offset, "output_sample_bytes": len(sample),
                "output_first_24_hex": sample[:24].hex(),
                "finished_within_sample": decoder.eof,
            })
        except zlib.error:
            continue
        if len(matches) >= 12:
            break
    return matches


def inspect_iwd(filename: Path) -> dict:
    with zipfile.ZipFile(filename) as nested:
        infos = nested.infolist()
        if len(infos) > 100_000:
            raise ValueError("nested IWD has unexpectedly many members")
        kinds = Counter(classify(i.filename) for i in infos if not i.is_dir())
        image_names = sorted(
            i.filename for i in infos if not i.is_dir() and i.filename.lower().endswith(".iwi")
        )
        # Nested image bytes are not decoded or exported here.
        return {
            "member_count": len(infos),
            "types": dict(sorted(kinds.items())),
            "iwi_count": len(image_names),
            "iwi_name_examples": image_names[:20],
        }


def inspect_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, scratch: Path) -> dict:
    if info.file_size > MAX_SINGLE_BYTES:
        raise ValueError("source member exceeds single-file analysis cap")
    digest = hashlib.sha256()
    first = bytearray()
    target = scratch / "member.iwd"
    kind = classify(info.filename)
    save_nested = kind == "iwd" and info.file_size <= MAX_IWD_BYTES
    total = 0
    with zf.open(info) as source:
        with (target.open("wb") if save_nested else open(os.devnull, "wb")) as sink:
            while True:
                block = source.read(CHUNK)
                if not block:
                    break
                total += len(block)
                if total > MAX_SINGLE_BYTES:
                    raise ValueError("stream exceeded selected source limit")
                digest.update(block)
                if len(first) < SIGNATURE_BYTES:
                    first.extend(block[: SIGNATURE_BYTES - len(first)])
                if save_nested:
                    sink.write(block)
    if total != info.file_size:
        raise RuntimeError("ZIP original member was truncated")
    report = {
        "source_path": info.filename, "kind": kind, "size": total,
        "zip_crc32": f"{info.CRC:08x}", "sha256": digest.hexdigest(),
        "first_64_hex": bytes(first[:64]).hex(),
        "ascii_magic_8": "".join(chr(c) if 32 <= c < 127 else "." for c in first[:8]),
    }
    if kind == "fastfile":
        report["zlib_candidates_in_first_4096_bytes"] = zlib_candidates(first)
        if len(first) >= 12:
            report["u32le_at_8"] = int.from_bytes(first[8:12], "little")
    if save_nested:
        try:
            report["iwd_zip_directory"] = inspect_iwd(target)
        finally:
            target.unlink(missing_ok=True)
    return report


def select_members(infos: list[zipfile.ZipInfo], preset: str) -> list[zipfile.ZipInfo]:
    ff = [x for x in infos if classify(x.filename) == "fastfile"
          and x.file_size <= MAX_SINGLE_BYTES]
    iwd = [x for x in infos if classify(x.filename) == "iwd"
           and x.file_size <= MAX_IWD_BYTES]
    def score(info: zipfile.ZipInfo) -> tuple[int, int, str]:
        n = PurePosixPath(info.filename.lower()).name
        priority = 10
        if n in ("common_mp.ff", "patch_mp.ff"): priority = 0
        elif n in ("mp_dome.ff", "mp_hardhat.ff", "mp_terminal.ff"): priority = 1
        elif n.startswith("mp_"): priority = 2
        elif n.endswith("_mp.ff"): priority = 3
        return priority, info.file_size, info.filename.lower()
    ff.sort(key=score)
    iwd.sort(key=lambda i: (0 if "iw_" in i.filename.lower() else 1, i.file_size, i.filename))
    if preset == "inventory":
        return []
    if preset == "maps":
        chosen = [i for i in ff if PurePosixPath(i.filename.lower()).name.startswith("mp_")][:3]
    else:
        chosen = ff[:4]
    if iwd:
        chosen.append(iwd[0])
    budget = 0
    result = []
    for info in chosen:
        if budget + info.file_size > MAX_TOTAL_BYTES:
            continue
        result.append(info)
        budget += info.file_size
    return result


def run(output: Path, preset: str) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "iw5_source_report.json"
    report = {"source_url": SOURCE_URL, "preset": preset, "complete": False,
              "source_members_examined": [], "limitations": [
                  "No IW5 asset tables, world geometry, or shaders are claimed decoded by this inventory probe",
                  "Only selected source members are SHA256-verified; the complete ZIP is not downloaded",
              ]}
    try:
        size = remote_size(SOURCE_URL)
        report["remote_zip_bytes"] = size
        if size <= 0:
            raise RuntimeError("R2 source object was empty")
        with HttpRangeObject(SOURCE_URL, size) as reader:
            with zipfile.ZipFile(reader) as zf:
                infos = zf.infolist()
                if len(infos) > 250_000:
                    raise ValueError("unexpectedly large ZIP entry table")
                safe = [i for i in infos if not i.is_dir() and safe_member_name(i.filename)]
                report["zip_member_count"] = len(infos)
                report["safe_file_count"] = len(safe)
                report["type_counts"] = dict(sorted(Counter(classify(i.filename) for i in safe).items()))
                report["extensions"] = dict(Counter(
                    PurePosixPath(i.filename.lower()).suffix for i in safe).most_common(30))
                report["fastfile_examples"] = [i.filename for i in safe if classify(i.filename) == "fastfile"][:60]
                report["iwd_examples"] = [i.filename for i in safe if classify(i.filename) == "iwd"][:30]
                selected = select_members(safe, preset)
                report["selected_member_count"] = len(selected)
                if preset != "inventory" and not selected:
                    raise RuntimeError("No bounded MW3 source .ff/.iwd members located")
                with tempfile.TemporaryDirectory(prefix="iw5-original-") as temporary:
                    scratch = Path(temporary)
                    for i in selected:
                        metadata = inspect_member(zf, i, scratch)
                        report["source_members_examined"].append(metadata)
                        report_path.write_text(json.dumps(report, indent=2) + "\n")
        report["complete"] = True
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--preset", choices=("inventory", "focused", "maps"), default="focused")
    args = parser.parse_args()
    try:
        run(args.output_dir, args.preset)
    except Exception as e:
        print("IW5 R2 source audit failed:", e, file=sys.stderr)
        sys.exit(1)
