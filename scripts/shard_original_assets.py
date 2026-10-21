#!/usr/bin/env python3
"""Repackage complete original game files into GitHub-tool-sized artifacts.

The full source bytes are retained byte-for-byte, never sampled or replaced
by metadata-only output. POSIX hardlinks create an independent artifact tree
without duplicating original game bytes on an already space-limited runner.
Each artifact stays comfortably below the GitHub connector's 512 MiB limit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil

MAX_SHARD_BYTES = 300 * 1024 * 1024
MAX_SHARDS = 20


def shard_original_assets(root: Path, target: Path, shard_bytes: int = MAX_SHARD_BYTES):
    if not root.is_dir():
        raise ValueError("Original binary source directory does not exist")
    if shard_bytes <= 0:
        raise ValueError("Shard size must be positive")
    if target.exists():
        if any(target.iterdir()):
            raise ValueError("Artifact shard destination is not empty")
    else:
        target.mkdir(parents=True)
    files = sorted(f for f in root.rglob("*") if f.is_file())
    if not files:
        raise ValueError("No original game source files to retain")
    index, used = 0, 0
    sha256 = hashlib.sha256
    manifest = []
    for path in files:
        rel = path.relative_to(root)
        if ".." in rel.parts:
            raise ValueError("Unsafe original source relative path")
        size = path.stat().st_size
        if size > shard_bytes:
            # Existing source files are individual .ff/.iwd archives and must
            # remain intact. Do not invent a partial game format in the bridge.
            raise ValueError(
                f"Original file {rel} is {size} bytes and exceeds the transfer "
                f"shard size {shard_bytes}; raise shard size under 512 MiB."
            )
        if used + size > shard_bytes and used:
            index += 1
            used = 0
        if index >= MAX_SHARDS:
            raise ValueError("More than 20 transfer shards required; process batches")
        dst = target / f"part-{index:02d}" / "original-bo1" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(path, dst)
        except OSError:
            shutil.copyfile(path, dst)
        digest = sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        manifest.append({
            "path": rel.as_posix(),
            "size": size,
            "sha256": digest.hexdigest(),
            "part": index,
        })
        used += size
    (target / "transfer-manifest.json").write_text(
        json.dumps({"file_count": len(files), "shards": index+1, "files": manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Preserved {len(files)} complete original game files across {index+1} binary shards")
    for i in range(index+1):
        size=sum(f["size"] for f in manifest if f["part"]==i)
        print(f"  part-{i:02d}: {size:,} exact original bytes")
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--shard-mib", type=int, default=300)
    args=parser.parse_args()
    shard_original_assets(args.source,args.target,args.shard_mib*1024*1024)


if __name__=="__main__":
    main()
