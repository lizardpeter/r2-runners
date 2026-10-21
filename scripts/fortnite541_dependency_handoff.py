#!/usr/bin/env python3
"""Recover exact Fortnite 5.41 cooked Blueprint and mesh packages referenced
by original Athena POI UWorld actor records, with retail PAK SHA-1 proofs.

Input must be the ORIGINAL actor census emitted by the pinned public
Fortnite-reverse UE4.21 decoder on authenticated game packages.
The output retains complete original .uasset/.uexp/.ubulk payloads, not a
metadata-only report or reconstructed substitute. Unresolved identities
remain unresolved; ambiguous archive ownership never selects a guess.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

KEY = "81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A"
PREFIX = "FortniteGame/Content/"
ARCH_KINDS = ("Wall", "Roof", "Floor", "Corner", "Stairs")
SCOPE_ROOT = "/Game/Building/ActorBlueprints/"
CHUNK_BYTES = 8 * 1024 * 1024

def f_name_package(source: str) -> str:
    """Translate only the observed UE4 FName numbered package suffix."""
    package = source.split("::", 1)[0]
    if not package.startswith("/Game/") or any(part in ("", ".", "..")
        for part in package[6:].split("/")) or "\\" in package:
        raise ValueError("source package outside authenticated /Game namespace")
    def numbered(m: re.Match[str]) -> str:
        return "_" + str(int(m.group(1)) - 1)
    return re.sub(r"#([1-9][0-9]*)$", numbered, package)

def collect_frontier(log: str, scope: str) -> tuple[list[str], dict]:
    classes: Counter[str] = Counter()
    meshes: Counter[str] = Counter()
    rows = 0
    for line in log.splitlines():
        if line.startswith("ORIGINAL_541_POI_CLASS_FRONTIER "):
            match = re.search(
                r" inherited_classes=(\{.*?\}) scene_root_classes=(\{.*?\})",
                line,
            )
            if not match:
                raise ValueError("original source actor census lacks class map")
            classes.update(json.loads(match.group(1)))
            classes.update(json.loads(match.group(2)))
            rows += 1
        elif line.startswith("ORIGINAL_541_POI_ACTOR_SOURCE "):
            match = re.search(r" kind=direct_mesh source=(/Game/\S+)", line)
            if match:
                meshes[match.group(1)] += 1
    if rows < 3:
        raise ValueError("original Athena census missing REC, Warehouses, Pueblo")
    selected: Counter[str] = Counter()
    for source, instances in classes.items():
        if (scope == "all" or any(
            source.startswith(SCOPE_ROOT + kind + "/") for kind in ARCH_KINDS
        )):
            selected[f_name_package(source)] += instances
    for source, instances in meshes.items():
        selected[f_name_package(source)] += instances
    if not selected:
        raise ValueError("no original structural source packages identified")
    return sorted(selected), {
        "source_world_census_rows": rows,
        "original_inherited_class_identities": len(classes),
        "architectural_class_identities": sum(any(
            name.startswith(SCOPE_ROOT + kind + "/") for kind in ARCH_KINDS
        ) for name in classes),
        "architectural_class_placements": sum(count for name, count in classes.items()
            if any(name.startswith(SCOPE_ROOT + kind + "/") for kind in ARCH_KINDS)),
        "original_direct_static_mesh_identities": len(meshes),
        "requested_unique_source_packages": len(selected),
    }

def normalized_content_path(index_path: str) -> str | None:
    path = index_path.replace("\\", "/").lstrip("/")
    marker = PREFIX.lower()
    lower = path.lower()
    at = lower.find(marker)
    if at < 0 or (at > 0 and path[at - 1] != "/"):
        return None
    return lower[at + len(marker):]

def authenticated_archive_index():
    # These public tools perform original PAK v7 footer, encrypted-index AES,
    # and SHA-1 authentication before any file is accepted.
    sys.path.insert(0, str(Path("crates/fortnite_541/tools").resolve()))
    from fetch_remote_541_dependencies import PAKS
    from probe_remote_541_paks import BASE, authenticated_index, head, ranged
    candidates: dict[str, list[tuple]] = {}
    statuses = []
    for archive in PAKS:
        _, size, status = head(archive)
        if size is None:
            statuses.append({"archive": archive, "status": "not_available", "detail": status})
            continue
        entries, proof = authenticated_index(archive, size, KEY)
        if entries is None:
            statuses.append({"archive": archive, "status": "index_unverified", "detail": proof})
            continue
        statuses.append({"archive": archive, "status": "authenticated",
                         "index_proof": proof, "indexed_entries": len(entries)})
        for actual, record in entries.items():
            relative = normalized_content_path(actual)
            if relative is not None:
                candidates.setdefault(relative, []).append((archive, actual, record))
    if not any(s["status"] == "authenticated" for s in statuses):
        raise RuntimeError("none of the source PAK indexes authenticated")
    return BASE, ranged, candidates, statuses

def fetch_verified(entry: tuple, destination: Path, base: str, ranged) -> dict:
    archive, actual, record = entry
    offset, stored, unpacked, method, digest, encrypted = record
    if encrypted or method != 0 or stored != unpacked:
        raise ValueError("original entry compressed/encrypted; exact plain payload unavailable")
    if stored < 0 or offset < 0:
        raise ValueError("invalid original source range")
    url = base + "/" + archive
    header = ranged(url, offset, 53)
    if len(header) != 53 or struct.unpack_from("<QQQI", header, 0)[1:] != (stored, unpacked, 0):
        raise ValueError("original FPakEntry header inconsistent with authenticated PAK index")
    if header[28:48] != digest:
        raise ValueError("original FPakEntry SHA-1 not consistent with authenticated index")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        h = hashlib.sha1()
        with destination.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_BYTES), b""):
                h.update(chunk)
        if destination.stat().st_size != unpacked or h.digest() != digest:
            raise ValueError("existing source file differs from authenticated PAK")
        return {"path": str(destination), "bytes": unpacked, "sha1": digest.hex(),
                "source_archive": archive, "status": "verified_existing"}
    part = destination.with_name(destination.name + ".source-part")
    h = hashlib.sha1()
    try:
        with part.open("xb") as out:
            read = 0
            while read < stored:
                size = min(CHUNK_BYTES, stored - read)
                block = ranged(url, offset + 53 + read, size)
                if len(block) != size:
                    raise ValueError("R2 returned a truncated source range")
                h.update(block)
                out.write(block)
                read += size
        if read != unpacked or h.digest() != digest:
            raise ValueError("source payload SHA-1 does not match original PAK index")
        os.replace(part, destination)
    finally:
        part.unlink(missing_ok=True)
    return {"path": str(destination), "bytes": unpacked, "sha1": digest.hex(),
            "source_archive": archive, "status": "verified_download"}

def source_handoff(log: str, scope: str, destination: Path, report_dir: Path,
                   report_filename: str = "original-architecture-source-handoff.json") -> dict:
    packages, census = collect_frontier(log, scope)
    base, ranged, index, indexes = authenticated_archive_index()
    jobs: list[tuple[str,tuple]] = []
    unresolved = []
    for package in packages:
        relative = package[6:]
        by_extension = {}
        for ext in (".uasset", ".uexp", ".ubulk"):
            candidates = index.get((relative + ext).lower(), [])
            if len(candidates) > 1:
                # Same hash/bytes from multiple archives is unambiguous;
                # different contents require authenticated zone precedence
                # research, not an arbitrary first match.
                hashes = {(x[2][2], x[2][4]) for x in candidates}
                if len(hashes) == 1:
                    candidates = candidates[:1]
                else:
                    unresolved.append({"source_package": package, "extension": ext,
                                       "status": "conflicting_original_archive_ownership",
                                       "archives": [x[0] for x in candidates]})
                    continue
            if len(candidates) == 1:
                by_extension[ext] = candidates[0]
            elif ext in (".uasset", ".uexp"):
                unresolved.append({"source_package": package, "extension": ext,
                                   "status": "not_in_authenticated_source_indexes"})
        # A package pair is essential; do not confuse a single source file
        # with a fully importable cooked Blueprint/mesh package.
        if not all(e in by_extension for e in (".uasset", ".uexp")):
            continue
        for ext, entry in by_extension.items():
            path = destination / PREFIX / (relative + ext)
            jobs.append((package + ext, (entry, path, base, ranged)))
    completed = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(fetch_verified, *args): identity for identity, args in jobs}
        for future in as_completed(futures):
            identity = futures[future]
            try:
                result = future.result()
                result["source_identity"] = identity
                result["path"] = Path(result["path"]).relative_to(destination).as_posix()
                completed.append(result)
                print("ORIGINAL_541_EXACT_DEPENDENCY", identity, result["bytes"], result["sha1"], flush=True)
            except Exception as exc:
                unresolved.append({"source_identity": identity, "status": "download_or_validation_failed",
                                   "detail": str(exc)[:240]})
                print("ORIGINAL_541_DEPENDENCY_UNRESOLVED", identity, str(exc)[:240], flush=True)
    report = {
        "scope": scope, "census": census, "source_indexes": indexes,
        "verified_files": sorted(completed, key=lambda x:x["source_identity"]),
        "unresolved": sorted(unresolved, key=lambda x: (x.get("source_package",x.get("source_identity","")),x.get("extension",""))),
        "fully_closed": len(unresolved) == 0,
        "verified_payload_bytes": sum(r["bytes"] for r in completed),
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / report_filename).write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf8"
    )
    print("ORIGINAL_541_ARCHITECTURE_SOURCE_HANDOFF",
          "requested_packages", len(packages), "verified_files", len(completed),
          "unresolved", len(unresolved), "exact_bytes", report["verified_payload_bytes"],
          flush=True)
    if not completed:
        raise RuntimeError("no original architectural source packages recovered")
    return report

def self_test() -> None:
    source = (
        'ORIGINAL_541_POI_CLASS_FRONTIER REC original_world=Athena_POI_REC_001 '
        ' inherited_classes={"/Game/Building/ActorBlueprints/Wall/Factory_Wall#4::Factory_Wall_3_C": 3, '
        '"/Game/Building/ActorBlueprints/Roof/Factory_Roof::Factory_Roof_C": 2, '
        '"/Game/Gameplay/Trap::Trap_C": 1} scene_root_classes={}\n'
        'ORIGINAL_541_POI_CLASS_FRONTIER Warehouses original_world=Athena_POI_Warehouses_003 '
        ' inherited_classes={} scene_root_classes={}\n'
        'ORIGINAL_541_POI_CLASS_FRONTIER Pueblo original_world=Athena_POI_Pueblo_001 '
        ' inherited_classes={} scene_root_classes={}\n'
        'ORIGINAL_541_POI_ACTOR_SOURCE REC class=/Script/FortniteGame::FortStaticMeshActor '
        ' actor=Original_001 kind=direct_mesh source=/Game/Props/SM_A::SM_A'
    )
    names, census = collect_frontier(source, "architecture")
    assert names == ["/Game/Building/ActorBlueprints/Roof/Factory_Roof",
                     "/Game/Building/ActorBlueprints/Wall/Factory_Wall_3",
                     "/Game/Props/SM_A"]
    assert census["architectural_class_placements"] == 5
    assert f_name_package("/Game/Walls/Factory#19::Factory_18_C") == "/Game/Walls/Factory_18"
    assert normalized_content_path("/FortniteGame/Content/Props/SM_A.uasset") == "props/sm_a.uasset"
    for invalid in ("/Engine/SM_A::SM_A", "/Game/../Trap::Trap", "/Game/A\\Trap"):
        try:
            f_name_package(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe source identity accepted")
    print("FORTNITE_541_EXACT_ARCHITECTURE_HANDOFF_TEST_PASS",flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontier", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--scope", choices=("architecture", "all"), default="architecture")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        if not args.frontier or not args.destination or not args.report_dir:
            parser.error("--frontier --destination and --report-dir required")
        source_handoff(args.frontier.read_text(encoding="utf8"), args.scope,
                       args.destination, args.report_dir)
