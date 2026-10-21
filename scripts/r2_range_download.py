#!/usr/bin/env python3
"""Download an immutable public R2 source object in verified HTTP byte ranges.

Unlike a single GET, this avoids the upstream ~2 GiB response-body truncation
observed for T6 base.ipak. The size is a source identity check, not an artificial
size ceiling. All parts are exact consecutive original byte ranges.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from r2_download import validate_key


def fetch_exact_range(url: str, start: int, end: int, total: int, path: Path, etag: str | None) -> tuple[str, str | None]:
    part = path.with_suffix(path.suffix + ".incomplete")
    for attempt in range(4):
        digest = hashlib.sha256()
        try:
            with urlopen(Request(url, headers={
                "User-Agent": "r2-runners/1.0",
                "Range": f"bytes={start}-{end}",
                "Accept-Encoding": "identity",
            }), timeout=120) as response:
                if urlsplit(response.url).hostname != urlsplit(url).hostname:
                    raise ValueError("R2 ranged response changed origin host")
                if response.status != 206:
                    raise ValueError(f"R2 did not honor requested bytes {start}-{end}: HTTP {response.status}")
                expected_range = f"bytes {start}-{end}/{total}"
                got_range = response.headers.get("Content-Range", "")
                if got_range != expected_range:
                    raise ValueError(f"Unexpected Content-Range {got_range!r} vs {expected_range!r}")
                current_etag = response.headers.get("ETag")
                if etag and current_etag and etag != current_etag:
                    raise ValueError(f"R2 source ETag changed mid-download: {etag} to {current_etag}")
                size = 0
                with part.open("wb") as target:
                    while chunk := response.read(1024 * 1024):
                        target.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                if size != end - start + 1:
                    raise ValueError(f"Truncated range {start}-{end}: received {size}")
                part.replace(path)
                return digest.hexdigest(), etag or current_etag
        except Exception:
            part.unlink(missing_ok=True)
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://r2.houseofkublai.com")
    parser.add_argument("--key", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--chunk-size", type=int, default=384 * 1024 * 1024)
    args = parser.parse_args()
    source = urlsplit(args.base_url)
    if source.scheme != "https" or not source.hostname or source.path.rstrip("/"):
        parser.error("base-url must be an HTTPS origin")
    if args.expected_size <= 0 or args.chunk_size <= 0:
        parser.error("sizes must be positive")
    key = validate_key(args.key)
    url = args.base_url.rstrip("/") + "/" + quote(key, safe="/")
    parts_dir = args.output_dir / "base-parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    hashes = []
    etag = None
    full = hashlib.sha256()
    for i, start in enumerate(range(0, args.expected_size, args.chunk_size)):
        end = min(start + args.chunk_size, args.expected_size) - 1
        part = parts_dir / f"base.ipak.part-{i:02d}"
        part_digest, etag = fetch_exact_range(url, start, end, args.expected_size, part, etag)
        with part.open("rb") as stream:
            while data := stream.read(1024 * 1024):
                full.update(data)
        hashes.append({"file": part.name, "range_start": start, "range_end": end,
                       "bytes": end - start + 1, "sha256": part_digest})
        print(f"Source range {start}-{end} exact, SHA256={part_digest}", flush=True)
    total = sum(p["bytes"] for p in hashes)
    if total != args.expected_size:
        raise ValueError("Source parts do not add up to complete R2 object")
    record = {
        "source_key": key,
        "source_url": url,
        "source_bytes": total,
        "source_sha256": full.hexdigest(),
        "etag": etag,
        "parts": hashes,
        "verified": True,
        "reassembly_command": "cat base.ipak.part-* > base.ipak",
    }
    (parts_dir / "verification.json").write_text(json.dumps(record, indent=2) + "\n")
    (parts_dir / "full-object.sha256").write_text(
        f"{full.hexdigest()}  base.ipak\n"
    )
    (parts_dir / "parts.sha256").write_text(
        "".join(f"{r['sha256']}  {r['file']}\n" for r in hashes)
    )
    print(json.dumps({"source_key": key, "source_bytes": total,
                      "sha256": full.hexdigest(), "parts": len(hashes)}))


if __name__ == "__main__":
    main()
