#!/usr/bin/env python3
"""Sequentially inspect the owner's original IW5 ZIP over a normal HTTPS GET.

The custom R2 domain does not honor byte ranges for this 18.4 GB object.
No entire 18.4 GB copy is placed on disk. A small number of original source
FastFiles/prefixes are captured as ephemeral Actions artifacts for local R/E.
"""
from __future__ import annotations
from collections import Counter
import hashlib, json, os, re, sys
from pathlib import Path
from urllib.request import Request, urlopen
from stream_unzip import stream_unzip

URL = "https://r2.houseofkublai.com/downloads/games/pluto_iw5_full_game.zip"
EXPECTED_SIZE = 18424199780
CAPTURE_BUDGET = 64 * 1024 * 1024
MAX_PER_FILE = 32 * 1024 * 1024
PREFIX_SIZE = 256 * 1024
MAX_CAPTURE_FILES = 16

def chunks(stream, record):
    while True:
        buf = stream.read(1024 * 1024)
        if not buf:
            break
        record["network_bytes_read"] += len(buf)
        yield buf

def main(output: Path):
    output.mkdir(parents=True, exist_ok=True)
    samples = output / "source_samples"
    samples.mkdir(exist_ok=True)
    report_path = output / "original_iw5_zip_report.json"
    report = {"original_url": URL, "complete": False, "members": 0,
              "network_bytes_read": 0, "extensions": {}, "fastfiles": [], "samples": []}
    extensions = Counter()
    captured = 0
    try:
        req = Request(URL, headers={"User-Agent": "r2-runners/iw5-source-research", "Accept-Encoding": "identity"})
        with urlopen(req, timeout=180) as r:
            size = int(r.headers.get("Content-Length", "0"))
            if size != EXPECTED_SIZE:
                raise ValueError(f"unexpected original size {size}, expected {EXPECTED_SIZE}")
            for original_name, declared_size, entry_chunks in stream_unzip(chunks(r, report)):
                name = original_name.decode("utf-8", "replace")
                if "\0" in name or name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
                    raise ValueError(f"unsafe ZIP path: {name!r}")
                report["members"] += 1
                extensions[Path(name).suffix.lower()] += 1
                is_ff = name.lower().endswith(".ff")
                if is_ff:
                    report["fastfiles"].append(name)
                basename = Path(name).name.lower()
                priority = basename in ("common_mp.ff", "patch_mp.ff", "mp_dome.ff", "mp_hardhat.ff")
                capture = is_ff and len(report["samples"]) < MAX_CAPTURE_FILES and captured < CAPTURE_BUDGET
                limit = min(CAPTURE_BUDGET - captured, MAX_PER_FILE if priority else PREFIX_SIZE) if capture else 0
                local_name = f"{len(report['samples']):02d}_" + re.sub(r"[^a-zA-Z0-9_.-]", "_", name)[-128:]
                dest = samples / local_name
                first = bytearray()
                digest = hashlib.sha256()
                written = 0
                length = 0
                with (dest.open("wb") if capture else open(os.devnull, "wb")) as f:
                    for block in entry_chunks:
                        length += len(block)
                        if len(first) < 64:
                            first += block[:64-len(first)]
                        if capture and written < limit:
                            part = block[:limit - written]
                            f.write(part)
                            digest.update(part)
                            written += len(part)
                if capture and written:
                    report["samples"].append({
                        "path": name, "original_bytes": length, "saved_bytes": written,
                        "complete_file": written == length, "source_first64_hex": first.hex(),
                        "sample_sha256": digest.hexdigest(), "artifact_path": "source_samples/" + local_name})
                    captured += written
                if report["members"] % 200 == 0:
                    print(f"members {report['members']}, FF {len(report['fastfiles'])}, "
                          f"network {report['network_bytes_read']/1e9:.2f} GB", flush=True)
        report["complete"] = True
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        report["extensions"] = dict(extensions.most_common())
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k:v for k,v in report.items() if k != "fastfiles"}, indent=2), flush=True)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: iw5_stream_original.py OUTPUT_DIRECTORY")
    main(Path(sys.argv[1]))
