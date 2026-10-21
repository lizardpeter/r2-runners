#!/usr/bin/env python3
"""Read source files inside the owner's ORIGINAL 11.16 GB BO1 R2 ZIP by HTTP Range.

No complete ZIP download required. Only source-selected FastFiles and IWDs are
materialized on the GitHub runner, never published or committed to the public
repository. The audit artifact contains metadata only.
"""
from __future__ import annotations
import argparse
from collections import Counter, OrderedDict
import io
import json
import os
from pathlib import Path
import shutil
import sys
import zipfile
from urllib.request import Request, urlopen
from urllib.parse import quote

from bo1_probe import probe_ff, probe_iwd
from r2_download import download

R2_BASES = ("https://r2.houseofkublai.com/", "https://r2.xeniea.com/")
BO1_ZIP_KEY = "downloads/games/pluto_t5_full_game.zip"
EXPECTED_SIZE = 11_161_080_622
BLOCK_SIZE = 2 * 1024 * 1024
CACHE_BLOCKS = 12
MIN_SCRATCH_RESERVE = 512 * 1024 * 1024

class HttpRangeObject(io.RawIOBase):
    """Small bounded seekable reader suitable for Python's ZipFile, including ZIP64."""
    def __init__(self, url: str, size: int):
        super().__init__()
        self.url, self.size, self.pos = url, size, 0
        self.cache: OrderedDict[int, bytes] = OrderedDict()
        # Probe Range support rather than silently downloading an 11 GB body.
        self._block(0)

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_END: value = self.size + offset
        elif whence == io.SEEK_CUR: value = self.pos + offset
        elif whence == io.SEEK_SET: value = offset
        else: raise ValueError(f"Invalid seek origin {whence}")
        if value < 0: raise ValueError("Negative ZIP source seek")
        self.pos = value
        return self.pos

    def _block(self, index: int) -> bytes:
        if index in self.cache:
            self.cache.move_to_end(index)
            return self.cache[index]
        start = index * BLOCK_SIZE
        if start >= self.size: return b""
        end = min(start + BLOCK_SIZE, self.size) - 1
        request = Request(self.url, headers={
            "Range": f"bytes={start}-{end}",
            "Accept-Encoding": "identity",
            "User-Agent": "r2-runners/bo1-remote-zip/1.0",
        })
        with urlopen(request, timeout=90) as response:
            if response.status != 206:
                raise RuntimeError(
                    f"R2 server did not honor Range: HTTP {response.status}, "
                    f"Content-Range={response.headers.get('Content-Range')}, "
                    f"Content-Length={response.headers.get('Content-Length')}"
                )
            returned = response.headers.get("Content-Range", "")
            if returned != f"bytes {start}-{end}/{self.size}":
                raise RuntimeError(f"Unexpected R2 Content-Range: {returned}")
            data = response.read(BLOCK_SIZE + 1)
        if len(data) != end - start + 1:
            raise RuntimeError("R2 byte-range was truncated or oversized")
        self.cache[index] = data
        if len(self.cache) > CACHE_BLOCKS:
            self.cache.popitem(last=False)
        return data

    def read(self, size: int = -1) -> bytes:
        if self.pos >= self.size: return b""
        if size < 0:
            # ZipFile deliberately calls read() without a length while it
            # scans the final 65,557 bytes for EOCD/ZIP64 metadata. Permit
            # that bounded tail-read, but never allow an accidental read()
            # from the beginning to pull all 11 GB into memory.
            remaining = self.size - self.pos
            if remaining > 128 * 1024:
                raise RuntimeError(
                    f"Unbounded BO1 ZIP read exceeds safe trailing-window limit: {remaining}"
                )
            size = remaining
        size = min(size, self.size - self.pos)
        chunks = []
        while size:
            index, inner = divmod(self.pos, BLOCK_SIZE)
            data = self._block(index)
            piece = data[inner:inner + size]
            if not piece: raise RuntimeError("R2 range block did not contain requested data")
            chunks.append(piece)
            self.pos += len(piece)
            size -= len(piece)
        return b"".join(chunks)


def relative_original_member(path: str) -> str | None:
    clean = path.replace("\\", "/").strip("/")
    if ".." in clean.split("/") or not clean:
        return None
    bits = clean.split("/")
    for root in ("zone", "main"):
        if root in bits:
            return "/".join(bits[bits.index(root):])
    return None


def choose_entries(
    items: list[zipfile.ZipInfo], preset: str,
    iwd_start: int = 0, iwd_count: int | None = 4,
) -> tuple[list[tuple[str,zipfile.ZipInfo]], dict]:
    matches: dict[str, list[zipfile.ZipInfo]] = {}
    extensions = Counter()
    for entry in items:
        if entry.is_dir(): continue
        extensions[Path(entry.filename).suffix.lower()] += 1
        logical = relative_original_member(entry.filename)
        if logical:
            matches.setdefault(logical.lower(), []).append(entry)
    required = {"zone/common/common_mp.ff", "zone/common/patch_mp.ff"}
    if preset == "both":
        required.update({"zone/common/mp_nuked.ff", "zone/common/mp_firingrange.ff"})
    elif preset == "nuketown":
        required.add("zone/common/mp_nuked.ff")
    elif preset == "firingrange":
        required.add("zone/common/mp_firingrange.ff")
    elif preset == "all_multiplayer":
        required.update(p for p in matches if p.startswith("zone/common/mp_") and p.endswith(".ff"))
    # Any original client IWD can be selected, including the entire source
    # inventory. Batch only when actual temporary runner disk is insufficient.
    iwd_candidates = sorted(p for p in matches if p.startswith("main/") and p.endswith(".iwd"))
    if iwd_start < 0 or (iwd_count is not None and iwd_count < 0):
        raise ValueError("IWD source range must be nonnegative")
    selected_iwds = iwd_candidates[iwd_start:] if iwd_count is None else iwd_candidates[iwd_start:iwd_start+iwd_count]
    required.update(selected_iwds)
    selected = []
    missing = []
    for name in sorted(required):
        candidates = matches.get(name, [])
        if len(candidates) > 1:
            raise ValueError(f"Ambiguous source paths for {name}: {len(candidates)}")
        if not candidates:
            missing.append(name)
        else:
            selected.append((name, candidates[0]))
    catalog = {
        "total_zip_members": len(items),
        "extensions": dict(extensions.most_common(30)),
        "original_iwd_count": len(iwd_candidates),
        "original_iwd_examples": iwd_candidates[:20],
        "selected_iwd_start": iwd_start,
        "selected_iwd_count": len(selected_iwds),
        "original_zone_ff_count": sum(1 for p in matches if p.startswith("zone/") and p.endswith(".ff")),
        "missing_selected": missing,
    }
    return selected, catalog


def run(
    preset: str, output_dir: Path,
    iwd_start: int = 0, iwd_count: int | None = 4,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    reports = output_dir / "report"
    reports.mkdir(exist_ok=True)
    report = {"source_r2_key": BO1_ZIP_KEY, "source_zip_expected_bytes": EXPECTED_SIZE,
              "preset": preset, "member_report": [], "complete": False}
    path = reports / "bo1-full-game-range-report.json"
    try:
        failures = []
        source = None
        for base in R2_BASES:
            try:
                source = HttpRangeObject(base + quote(BO1_ZIP_KEY, safe="/"), EXPECTED_SIZE)
                report["source_mode"] = "bounded_http_ranges"
                report["source_host"] = base
                break
            except Exception as error:
                failures.append(f"{base}: {error}")
        report["range_probe_results"] = failures
        if source is None:
            # GitHub runners provide temporary storage, not a repo checkout.
            # Never attempt an 11 GB GET if there is insufficient scratch disk.
            available = shutil.disk_usage(output_dir).free
            # The complete original archive may be downloaded to runner disk;
            # available scratch for selected files is measured separately.
            required = EXPECTED_SIZE + MIN_SCRATCH_RESERVE + 512 * 1024 * 1024
            if available < required:
                raise RuntimeError(
                    f"R2 Range failed and scratch has only {available} free "
                    f"(needs {required}); range failures: {failures}"
                )
            full_source = output_dir / "original-full-game.zip"
            url = R2_BASES[0] + quote(BO1_ZIP_KEY, safe="/")
            transferred, digest, _ = download(url, full_source, EXPECTED_SIZE)
            if transferred != EXPECTED_SIZE:
                raise RuntimeError(
                    f"Full original ZIP download size {transferred} != {EXPECTED_SIZE}"
                )
            report["source_mode"] = "verified_full_runner_local_zip"
            report["original_zip_sha256"] = digest
            source = full_source.open("rb")
        with source:
            with zipfile.ZipFile(source) as archive:
                selected, catalog = choose_entries(
                    archive.infolist(), preset, iwd_start, iwd_count,
                )
                report["catalog"] = catalog
                report["zip64_range_open_succeeded"] = True
                if catalog["missing_selected"]:
                    raise RuntimeError("Original full game ZIP lacks requested source assets")
                total = sum(x.file_size for _,x in selected)
                available = shutil.disk_usage(output_dir).free
                if total + MIN_SCRATCH_RESERVE > available:
                    raise ValueError(
                        f"Requested original client files total {total} bytes, "
                        f"but only {available} bytes remain on runner disk. "
                        "Request a smaller --iwd-count or a larger runner."
                    )
                scratch = output_dir / "original-bo1"
                for rel, info in selected:
                    target = scratch.joinpath(*rel.split("/"))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info, "r") as read, target.open("wb") as write:
                        shutil.copyfileobj(read, write, 1024*1024)
                    if target.stat().st_size != info.file_size:
                        raise RuntimeError("Original ZIP member truncated")
                    datum = {"path": rel, "size": info.file_size,
                             "crc32": f"{info.CRC:08x}", "source_compression": info.compress_type}
                    if rel.endswith(".ff"):
                        datum["t5_fastfile"] = probe_ff(target.read_bytes())
                    elif rel.endswith(".iwd"):
                        datum["iwd"] = probe_iwd(target)
                    report["member_report"].append(datum)
                    path.write_text(json.dumps(report,indent=2)+"\n")
        report["complete"] = True
    except Exception as exc:
        report["error"] = str(exc)
        raise
    finally:
        path.write_text(json.dumps(report,indent=2)+"\n", encoding="utf-8")
        print(json.dumps({k:v for k,v in report.items() if k!="member_report"},indent=2))
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as f:
                f.write(f"### Original 11.16 GB BO1 archive ranged inspection\n\n"
                        f"- ZIP directory opened: {report.get('zip64_range_open_succeeded',False)}\n"
                        f"- Extracted source members to scratch: {len(report['member_report'])}\n"
                        f"- Completed: {report['complete']}\n"
                        f"- Original binary files retained for artifact transfer\n")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--preset", choices=["nuketown","firingrange","both","all_multiplayer"], default="both")
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--iwd-start", type=int, default=0,
                   help="Starting archive index within the original client IWD inventory")
    p.add_argument("--iwd-count", type=int, default=4,
                   help="Complete IWD archives to extract (0 selects all remaining)")
    args=p.parse_args()
    run(args.preset,args.output_dir,args.iwd_start,
        None if args.iwd_count == 0 else args.iwd_count)

if __name__ == "__main__":
    try: main()
    except Exception as e:
        print(f"BO1 ZIP64 range probe failed: {e}",file=sys.stderr)
        sys.exit(1)
