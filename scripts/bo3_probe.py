#!/usr/bin/env python3
"""Evidence-only BO3/T7 original-archive inspection on ephemeral R2 runners.

This does not decode unverified records or publish original game bytes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import zlib
import sys
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

ORIGIN = "https://r2.houseofkublai.com"
PREFIX = "bo3/DUMP/zone/"
MAX_PROBE_BYTES = 2 * 1024 * 1024
REPORT_DIR = Path(os.environ.get("BO3_REPORT_DIR", "reports/bo3"))
# Object sizes are from the account's authenticated R2 List Objects API.
SOURCES = {
    "core_all.ff": 704,
    "en_core_common.ff": 545024,
    "core_pre_gfx.ff": 22285376,
    "core_gfx.ff": 6790208,
    "core_gfx.xpak": 786432,
    "base_patch_tu32.xpak": 1048576,
    "core_common.ff": 198927488,
}
PRESETS = {
    "small": ("core_all.ff", "en_core_common.ff", "core_gfx.xpak", "base_patch_tu32.xpak"),
    "extended": tuple(SOURCES),
}

def select_keys() -> list[str]:
    preset = os.environ.get("BO3_PRESET", "small")
    if preset not in PRESETS:
        raise ValueError("Unknown BO3 preset")
    names = PRESETS[preset]
    return [PREFIX + name for name in names]

def read_bounded(key: str, expected_size: int, sample_size: int = MAX_PROBE_BYTES) -> tuple[bytes, dict]:
    if not key.startswith(PREFIX) or key[len(PREFIX):] not in SOURCES:
        raise ValueError("Only allowlisted original BO3 zone keys may be fetched")
    if sample_size < 256 or sample_size > MAX_PROBE_BYTES:
        raise ValueError("Probe limit out of range")
    url = ORIGIN + "/" + quote(key, safe="/")
    request = Request(url, headers={
        "Range": f"bytes=0-{min(expected_size, sample_size)-1}",
        "User-Agent": "r2-runners-bo3-source-probe/1.0",
        "Accept-Encoding": "identity",
    })
    with urlopen(request, timeout=90) as response:
        if urlsplit(response.url).hostname != urlsplit(ORIGIN).hostname:
            raise ValueError("Untrusted redirect")
        status = response.status
        response_range = response.headers.get("Content-Range", "")
        if status == 206:
            if not response_range.startswith("bytes 0-"):
                raise ValueError(f"Unexpected Content-Range: {response_range}")
            total = response_range.rsplit("/", 1)[-1]
            if total.isdigit() and int(total) != expected_size:
                raise ValueError(f"Unexpected original size {total}, expected {expected_size}")
        elif status == 200:
            declared = response.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) != expected_size:
                raise ValueError(f"Unexpected original size {declared}, expected {expected_size}")
        else:
            raise ValueError(f"HTTP {status} for {key}")
        limit = min(expected_size, sample_size)
        payload = response.read(limit + 1)
        if len(payload) > limit:
            # Range was ignored. We intentionally did not stream an entire large file.
            payload = payload[:limit]
        if len(payload) != limit:
            raise ValueError(f"Truncated original sample: {len(payload)} != {limit}")
    meta = {
        "http_status": status, "content_range": response_range or None,
        "sample_bytes": len(payload), "expected_source_bytes": expected_size,
        "sample_is_complete": len(payload) == expected_size,
    }
    return payload, meta


def decode_zlib_fastfile_sample(payload: bytes, file_bytes: int) -> dict:
    """Decode only complete, bounded T7 zlib blocks, from real retail bytes."""
    if not payload.startswith(b"TAff0000"):
        raise ValueError("Not T7 FastFile")
    version = struct.unpack_from("<I", payload, 8)[0]
    compression = payload[13]
    start = {0x251: 0x248, 0x265: 0x638}.get(version)
    report = {"version": hex(version), "compression_id": compression,
              "block_table_start": start, "verified_blocks": [], "decoded_prefix_hex": "",
              "sample_incomplete": len(payload) < file_bytes}
    if start is None or compression != 1:
        report["block_status"] = "unsupported_version_or_non_zlib_codec"
        return report
    pos = start
    decoded = bytearray()
    for i in range(8):
        if pos + 16 > len(payload):
            report["block_status"] = "need_more_source_bytes"
            break
        compressed, uncompressed, block_size, offset = struct.unpack_from("<iiii", payload, pos)
        block = {"offset": pos, "compressed_bytes": compressed, "decoded_bytes": uncompressed,
                 "block_size_word": block_size, "block_position_word": offset}
        if block_size == 0:
            report["block_status"] = "source_end_marker"
            break
        if offset != pos or compressed < 0 or uncompressed < 0 or compressed > 8 * 1024 * 1024 or uncompressed > 32 * 1024 * 1024:
            report["block_status"] = "invalid_block_header"
            report["failed_block"] = block
            break
        end = pos + 16 + compressed
        if not uncompressed:
            report["block_status"] = "unsupported_empty_block_alignment"
            break
        if end > len(payload):
            report["block_status"] = "need_more_source_bytes"
            report["next_block"] = block
            break
        stream = zlib.decompressobj()
        raw = stream.decompress(payload[pos + 16:end], uncompressed + 1)
        raw += stream.flush()
        if len(raw) != uncompressed or not stream.eof or stream.unused_data:
            report["block_status"] = "zlib_size_or_eof_mismatch"
            report["failed_block"] = block
            break
        block["decoded_sha256"] = hashlib.sha256(raw).hexdigest()
        report["verified_blocks"].append(block)
        decoded.extend(raw[:max(0, 256 - len(decoded))])
        if block_size < compressed:
            report["block_status"] = "block_span_smaller_than_compressed_payload"
            break
        pos += 16 + block_size
    report["decoded_prefix_hex"] = bytes(decoded[:128]).hex()
    if len(decoded) >= 36:
        report["source_script_string_count"] = struct.unpack_from("<i", decoded, 0)[0]
        report["source_xasset_count"] = struct.unpack_from("<i", decoded, 32)[0]
    report["verified_decoded_bytes"] = sum(b["decoded_bytes"] for b in report["verified_blocks"])
    return report

def inspect(key: str, payload: bytes, meta: dict) -> dict:
    if len(payload) < 32:
        raise ValueError("Insufficient header bytes")
    words = list(struct.unpack_from("<16I", payload)) if len(payload) >= 64 else []
    def printable(b: bytes) -> str:
        return "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    patterns = {
        "zlib_78_01": b"\x78\x01",
        "zlib_78_9c": b"\x78\x9c",
        "zlib_78_da": b"\x78\xda",
        "zstd": b"\x28\xb5\x2f\xfd",
        "lz4_frame": b"\x04\x22\x4d\x18",
        "gzip": b"\x1f\x8b",
    }
    # Candidate positions are evidence, not proof of a valid compressed block.
    hits = {name: [] for name in patterns}
    scan = payload[: min(len(payload), 4096)]
    for name, marker in patterns.items():
        start = 0
        while len(hits[name]) < 8:
            at = scan.find(marker, start)
            if at < 0:
                break
            hits[name].append(at)
            start = at + 1
    # A partial sample is not a full-object hash.
    decoding = decode_zlib_fastfile_sample(payload, meta["expected_source_bytes"]) if key.endswith(".ff") else None
    return {
        "key": key, **meta, "sha256_sample": hashlib.sha256(payload).hexdigest(),
        "sha256_scope": "entire_object" if meta["sample_is_complete"] else "prefix_only",
        "header_ascii_32": printable(payload[:32]),
        "header_hex_128": payload[:128].hex(),
        "u32_le_first_16": words,
        "candidate_compression_signatures_first_4096": {k: v for k, v in hits.items() if v},
        "decoder_state": "authenticated_archive_blocks" if decoding and decoding["verified_blocks"] else "source_header_observed",
        "fastfile_block_decoder": decoding,
    }

def main() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for key in select_keys():
        size = SOURCES[key[len(PREFIX):]]
        print(f"Reading original BO3 archive sample {key} ({size} source bytes)", flush=True)
        payload, meta = read_bounded(key, size)
        entry = inspect(key, payload, meta)
        print(json.dumps(entry, sort_keys=True), flush=True)
        entries.append(entry)
    dest = REPORT_DIR / "bo3_archive_observations.json"
    dest.write_text(json.dumps({"origin": ORIGIN, "samples": entries}, indent=2) + "\n", encoding="utf-8")
    print(f"Saved source-authenticated metadata for {len(entries)} BO3 archives", flush=True)
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"BO3 source probe failed: {error}", file=sys.stderr)
        raise SystemExit(1)
