#!/usr/bin/env python3
"""Run real R2-source Ghosts inspections in disposable GitHub-runner storage.

Original retail game files are NEVER included in the workflow artifacts.
Only provenance, checksums, decoded asset counts, and failure details survive.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.parse import quote

from r2_download import download, validate_key

ORIGIN = "https://r2.houseofkublai.com"
SOURCE_PREFIX = "ghosts/DUMP/"
MAX_FILE_BYTES = 850 * 1024 * 1024
MAX_FILES = 32
# Measured from the owner's actual R2 objects, and verified against decoded
# authenticated FastFiles on the independent original-source research runner.
VERIFIED = {
    "mp_alien_town_path.ff": (385068, 1441055, 5239, 2,
        "53568ffa28c9bec2b57679c0bc0cb02983a44972dfac9679ca92918e0de5993a"),
    "techsets_mp_alien_town.ff": (7479340, 58840896, 1032, 842,
        "a241655f715e477379f96a6b1e4ab74c7447cf826a257e229217fed6c4311e45"),
    "mp_alien_town_load.ff": (1957932, 14325979, 328, 67,
        "7df4123f9db38f7f827ef1d67fce64226af03d1576fcdc82f692ca9dc35f6399"),
    "mp_alien_town.ff": (186301740, 347242545, 57460, 2560,
        "f377282c4606064c253be50e07f366f170a53fa16df87af96776a4fbc7ae4900"),
}
GROUPS = {
    "point-of-contact": list(VERIFIED),
    "other-maps": ["mp_alien_armory.ff", "mp_alien_beacon.ff",
                    "mp_strikezone.ff", "black_ice.ff"],
}
OTHER_SIZES = {
    "mp_alien_armory.ff": 249387180,
    "mp_alien_beacon.ff": 197856300,
    "mp_strikezone.ff": 138884972,
    "black_ice.ff": 333564502,
}


def requested_keys() -> list[str]:
    raw = os.environ.get("R2_OBJECT_KEYS", "").strip()
    group = os.environ.get("R2_GROUP", "point-of-contact")
    if raw:
        keys = [line.strip() for line in raw.replace(",", "\n").splitlines() if line.strip()]
    else:
        if group not in GROUPS:
            raise ValueError(f"Unknown source group: {group}")
        keys = [SOURCE_PREFIX + n for n in GROUPS[group]]
    if not keys or len(keys) > MAX_FILES:
        raise ValueError(f"Provide between 1 and {MAX_FILES} object keys")
    # Paths are always relative to the one trusted HTTPS origin.
    keys = [validate_key(key) for key in keys]
    if len(set(keys)) != len(keys):
        raise ValueError("Duplicate object keys are not permitted")
    return keys


def inspect_fastfile(source: Path, checkout: Path) -> dict:
    parser = checkout / "tools" / "fastfile" / "probe_asset_directory.py"
    if not parser.is_file():
        raise ValueError(f"Public source parser not checked out: {parser}")
    result = subprocess.run(
        [sys.executable, str(parser), str(source)],
        capture_output=True, text=True, timeout=240, check=False,
    )
    if result.returncode:
        raise RuntimeError(
            "Original-source decoder failed: " + result.stderr[-2800:]
        )
    lines = [s.strip() for s in result.stdout.splitlines() if s.strip()]
    if not lines:
        raise RuntimeError("Original-source decoder did not return a report")
    report = json.loads(lines[-1])
    if report.get("status") != "retail_compressed_stream_verified_and_xasset_prelude_walked":
        raise RuntimeError("Original signed FastFile stream or XAsset directory unverified")
    return report


def emit_report(data: dict) -> None:
    print(json.dumps(data, sort_keys=True), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(
                f"- `{data['object_key']}`: **{data['input_bytes']:,} bytes**; "
                f"SHA-256 `{data['source_sha256']}`; "
                f"{data.get('xasset_count', 'not checked')} XAssets\n"
            )


def main() -> int:
    mode = os.environ.get("R2_MODE", "iw6-directory")
    if mode not in ("fingerprint", "iw6-directory"):
        raise ValueError("Mode must be fingerprint or iw6-directory")
    checkout = Path(os.environ.get("RESEARCH_CHECKOUT", "research"))
    reports = Path(os.environ.get("R2_REPORT_DIR", "reports"))
    reports.mkdir(parents=True, exist_ok=True)
    keys = requested_keys()
    all_reports: list[dict] = []
    for index, key in enumerate(keys):
        name = key.rsplit("/", 1)[-1]
        if mode == "iw6-directory" and (
            not key.startswith(SOURCE_PREFIX) or not name.lower().endswith(".ff")
        ):
            raise ValueError("IW6 directory analysis requires a Ghosts/DUMP .ff object")
        with TemporaryDirectory(prefix="r2-research-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
            target = Path(temporary) / name
            print(f"Downloading original R2 object {index+1}/{len(keys)}: {key}", flush=True)
            size, sha256, content_type = download(
                ORIGIN + "/" + quote(key, safe="/"), target, MAX_FILE_BYTES
            )
            expected = VERIFIED.get(name)
            known_size = expected[0] if expected is not None else OTHER_SIZES.get(name)
            if known_size is not None and size != known_size:
                raise ValueError(f"{name}: original source size mismatch: {size} vs {known_size}")
            data = {
                "object_key": key,
                "source_sha256": sha256,
                "input_bytes": size,
                "content_type": content_type,
                "bytes_held": "temporary-runner-disk-only",
            }
            if mode == "iw6-directory":
                original = inspect_fastfile(target, checkout)
                if original["file"] != name:
                    raise ValueError("Original decoder returned different source name")
                if expected is not None:
                    expected_len, decoded_len, directory_offset, count, digest = expected
                    if (original["original_size"] != expected_len
                            or original["decoded_size"] != decoded_len
                            or original["exact_asset_table_offset"] != directory_offset
                            or original["asset_count"] != count
                            or original["decoded_sha256"] != digest
                            or original["unverified_partial_tail_bytes"] != 0):
                        raise ValueError(f"Authenticated retail-source contract failed for {name}")
                if name == "mp_alien_town_path.ff":
                    probe = subprocess.run(
                        [sys.executable, "scripts/iw6_pathdata_source.py",
                         str(checkout / "tools" / "fastfile"), str(target)],
                        capture_output=True, text=True, timeout=180, check=False,
                    )
                    if probe.returncode:
                        raise RuntimeError(
                            "Original PathData node probe failed: " + probe.stderr[-2000:]
                        )
                    node_data = json.loads(probe.stdout.strip().splitlines()[-1])
                    if node_data["decoded_sha256"] != original["decoded_sha256"]:
                        raise ValueError("Original PathData nodes came from a different decoded FastFile")
                    data["original_pathnode_evidence"] = node_data
                data.update({
                    "authenticated_blocks": original["authenticated_sha256_blocks"],
                    "decoded_bytes": original["decoded_size"],
                    "decoded_sha256": original["decoded_sha256"],
                    "original_directory_offset": original["exact_asset_table_offset"],
                    "xasset_count": original["asset_count"],
                    "type_counts": original["type_counts"],
                    "first_unsupported_body_type": original.get("first_unsupported_body_type"),
                    "pathdata_header_probe": original.get("pathdata_header_probe"),
                    "first_netconst_body_probe": original.get("first_netconst_body_probe"),
                })
            emit_report(data)
            all_reports.append(data)
            # TemporaryDirectory destroys original data before next file.
    (reports / "verification.json").write_text(
        json.dumps({"mode": mode, "files": all_reports}, indent=2) + "\n",
        encoding="utf-8"
    )
    print(f"Verified {len(all_reports)} original R2 objects. No game files exported.", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Original R2 source verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
