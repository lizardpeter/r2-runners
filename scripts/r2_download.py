#!/usr/bin/env python3
"""Download and validate public Cloudflare R2 objects on a network-enabled runner."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

DEFAULT_SAMPLE = "Downloads/HOK_Gamerpics/512_HK_Holder.png"
PNG_SIGNATURE = bytes.fromhex("89504e470d0a1a0a")


def validate_key(key: str) -> str:
    # Prevent escape from the fixed public origin and reject ambiguous URL paths.
    if (
        not key
        or key.startswith("/")
        or "\\" in key
        or any(part in ("", ".", "..") for part in key.split("/"))
        or any(ord(ch) < 32 for ch in key)
    ):
        raise ValueError("Invalid R2 object key")
    return key


def download(url: str, dest: Path, max_bytes: int) -> tuple[int, str, str]:
    part = dest.with_suffix(".part")
    for attempt in range(3):
        digest = hashlib.sha256()
        count = 0
        try:
            request = Request(url, headers={"User-Agent": "r2-runners/1.0"})
            with urlopen(request, timeout=90) as response, part.open("wb") as output:
                origin_host = urlsplit(url).hostname
                final_host = urlsplit(response.url).hostname
                if final_host != origin_host:
                    raise ValueError(f"Unexpected redirect host: {final_host}")
                size_header = response.headers.get("Content-Length")
                if size_header and int(size_header) > max_bytes:
                    raise ValueError(f"Object size {size_header} exceeds max {max_bytes}")
                content_type = response.headers.get("Content-Type", "")
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    if count > max_bytes:
                        raise ValueError(f"Downloaded object exceeds limit of {max_bytes} bytes")
                    digest.update(chunk)
                    output.write(chunk)
            os.replace(part, dest)
            return count, digest.hexdigest(), content_type
        except Exception:
            part.unlink(missing_ok=True)
            if attempt == 2:
                raise
            time.sleep(2**attempt)
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-size", type=int)
    parser.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024 * 1024,
                        help="Maximum object size; bounded by runner disk and artifact limits")
    args = parser.parse_args()

    key = validate_key(args.key)
    base = urlsplit(args.base_url)
    if base.scheme != "https" or not base.netloc or base.username or base.password or base.path.rstrip("/"):
        parser.error("--base-url must be an HTTPS origin with no path or credentials")
    if args.max_bytes <= 0:
        parser.error("Byte limits must be valid")

    url = args.base_url.rstrip("/") + "/" + quote(key, safe="/")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_file = args.output_dir / "downloaded-object.bin"
    byte_count, sha256, content_type = download(url, output_file, args.max_bytes)

    if args.expected_size is not None and byte_count != args.expected_size:
        raise ValueError(f"Size mismatch: expected {args.expected_size}, downloaded {byte_count}")
    if key == DEFAULT_SAMPLE and output_file.open("rb").read(8) != PNG_SIGNATURE:
        raise ValueError("Expected PNG signature is missing")

    report = {
        "object_key": key,
        "source_url": url,
        "bytes_downloaded": byte_count,
        "sha256": sha256,
        "content_type": content_type,
        "expected_size_verified": args.expected_size is not None,
        "signature_verified": key == DEFAULT_SAMPLE,
    }
    artifact_dir = args.output_dir / "artifact"
    artifact_file = artifact_dir.joinpath(*key.split("/"))
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    # Keep every byte at its original R2 key-relative path, including large files.
    # A move avoids doubling scratch disk usage on the runner.
    os.replace(output_file, artifact_file)
    (artifact_dir / "verification.json").write_text(
        json.dumps({**report, "artifact_path": key}, indent=2) + "\n",
        encoding="utf-8"
    )

    summary = (
        f"### Public R2 binary download succeeded\n\n"
        f"- Object: \`{key}\`\n"
        f"- Bytes: {byte_count}\n"
        f"- SHA-256: \`{sha256}\`\n"
        f"- Exact original bytes staged at: \`{artifact_file}\` (runner temporary directory)\n"
    )
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"R2 transfer or validation failed: {error}", file=sys.stderr)
        sys.exit(1)
