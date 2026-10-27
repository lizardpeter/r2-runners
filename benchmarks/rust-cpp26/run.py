#!/usr/bin/env python3
"""Reproducible Rust 1.99.1 vs C++26 microbenchmark: stdlib only."""
import argparse
import csv
import json
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TASKS = ("hash", "scan", "gather", "sort")
SEEDS = (42066123, 20261026)

def run_cmd(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, check=True, **kw)

def version(cmd):
    if not shutil.which(cmd[0]):
        return "unavailable"
    try:
        return run_cmd(cmd).stdout.strip()
    except Exception as e:
        return f"error: {e}"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--trials", type=int, default=7)
    p.add_argument("--warmups", type=int, default=2)
    p.add_argument("--out", type=Path, default=ROOT / "results")
    p.add_argument("--strict", action="store_true", help="require both C++ and Rust")
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    configs = []
    for compiler, flag, name in (("g++", "-std=c++26", "gcc-cpp26"),
                                 ("clang++", "-std=c++2c", "clang-cpp2c")):
        if shutil.which(compiler):
            for opt in (0, 2, 3):
                output = args.out / f"{name}-O{opt}"
                cmd = [compiler, flag, f"-O{opt}", "-march=x86-64", "-fno-lto",
                       str(ROOT / "bench.cpp"), "-o", str(output)]
                try:
                    run_cmd(cmd)
                except subprocess.CalledProcessError as e:
                    print(f"Skipping {' '.join(cmd)}: {e.stderr}", file=sys.stderr)
                    continue
                configs.append({"label": f"{name}-O{opt}", "exe": str(output), "build": cmd})
    if shutil.which("g++"):
        output = args.out / "gcc-cpp26-O3-hardened"
        cmd = ["g++", "-std=c++26", "-O3", "-march=x86-64",
               "-fno-lto", "-D_GLIBCXX_ASSERTIONS",
               str(ROOT / "bench.cpp"), "-o", str(output)]
        run_cmd(cmd)
        configs.append({"label": "gcc-cpp26-O3-hardened", "exe": str(output), "build": cmd})
    if shutil.which("rustc"):
        rust_version = version(["rustc", "--version"])
        if not rust_version.startswith("rustc 1.99.1 "):
            raise SystemExit(f"This test requires Rust 1.99.1, found {rust_version}")
        for opt in (0, 2, 3):
            output = args.out / f"rust-1.99.1-O{opt}"
            cmd = ["rustc", "--edition=2024", f"-Copt-level={opt}",
                   "-Ccodegen-units=1", "-Clto=off", "-Ctarget-cpu=x86-64",
                   str(ROOT / "bench.rs"), "-o", str(output)]
            run_cmd(cmd)
            configs.append({"label": f"rust-O{opt}", "exe": str(output), "build": cmd})
    if args.strict and not any(c["label"].startswith("rust-") for c in configs):
        raise SystemExit("Strict mode: rustc not installed. No Rust timings claimed.")
    if not configs:
        raise SystemExit("No toolchain available")
    metadata = {"host": platform.node(), "os": platform.platform(),
                "machine": platform.machine(), "processor": platform.processor(),
                "rustc": version(["rustc", "--version", "--verbose"]),
                "gcc": version(["g++", "--version"]).splitlines()[0],
                "clang": version(["clang++", "--version"]).splitlines()[0],
                "configs": configs, "trials": args.trials, "warmups": args.warmups,
                "seeds": SEEDS, "tasks": TASKS,
                "limitations": ["uncontrolled shared/virtualized CPU; not hardware-isolated",
                                 "sorting uses different unstable-sort algorithms",
                                 "standard libraries are precompiled in release mode",
                                 "no PGO/LTO, baseline x86-64 CPU target",
                                 "within-process timers exclude process launch but include task setup",
                                 "libstdc++ assertions variant is not comprehensive memory safety"]}
    try:
        metadata["cpuinfo"] = Path("/proc/cpuinfo").read_text().split("model name\t: ")[1].splitlines()[0]
    except (IndexError, OSError):
        metadata["cpuinfo"] = "unknown"
    (args.out / "metadata.json").write_text(json.dumps(metadata, indent=2))
    cases = [(task, seed) for task in TASKS for seed in SEEDS]
    configs_by_label = {c["label"]: c for c in configs}
    rows = []
    checksums = {}
    rounds = args.warmups + args.trials
    rng = random.Random(20261026)
    for trial in range(rounds):
        planned = [(case, label) for case in cases for label in configs_by_label]
        rng.shuffle(planned)
        for (task, seed), label in planned:
            c = configs_by_label[label]
            p = run_cmd([c["exe"], task, str(seed)], timeout=180)
            match = re.fullmatch(r"checksum=([0-9a-f]{16})\s+elapsed_ns=(\d+)\s*", p.stdout)
            if not match:
                raise RuntimeError(f"Unrecognized stdout from {label}: {p.stdout!r}")
            checksum, elapsed_ns = match.group(1), int(match.group(2))
            key = (task, seed)
            if key in checksums and checksums[key] != checksum:
                raise RuntimeError(f"CHECKSUM MISMATCH {key}: expected {checksums[key]} got {checksum} from {label}")
            checksums[key] = checksum
            if trial >= args.warmups:
                rows.append({"language_toolchain": label, "task": task, "seed": seed,
                             "trial": trial - args.warmups + 1,
                             "elapsed_ns": elapsed_ns, "checksum": checksum})
        print(f"Finished round {trial + 1}/{rounds}", flush=True)
    with (args.out / "samples.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    grouped = {}
    for row in rows:
        grouped.setdefault((row["language_toolchain"], row["task"]), []).append(row["elapsed_ns"] / 1e6)
    summary = [{"toolchain": label, "task": task, "median_ms": round(statistics.median(vals), 4),
                "min_ms": round(min(vals), 4), "max_ms": round(max(vals), 4),
                "n": len(vals)}
               for (label, task), vals in sorted(grouped.items())]
    with (args.out / "summary.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0]))
        writer.writeheader(); writer.writerows(summary)
    (args.out / "checksums.json").write_text(json.dumps(
        {f"{task}|{seed}": checksum for (task, seed), checksum in sorted(checksums.items())}, indent=2))
    print("\ntoolchain,task,median_ms,n")
    for x in summary:
        print(f"{x['toolchain']},{x['task']},{x['median_ms']},{x['n']}")
    print(f"\nSaved results under {args.out}")

if __name__ == "__main__":
    main()
