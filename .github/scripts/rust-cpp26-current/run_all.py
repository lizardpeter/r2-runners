#!/usr/bin/env python3
"""Same-host paired Rust/GCC/Clang current-and-prior compiler benchmark."""
import argparse, csv, json, os, platform, random, re, shutil, statistics, subprocess, sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[3] / "benchmarks/rust-cpp26"
TASKS = ("hash", "scan", "gather", "sort")
SEEDS = (42066123, 20261026)

def command(argv, **kwargs):
    return subprocess.run([str(x) for x in argv], check=True, capture_output=True,
                          text=True, **kwargs)

def version(exe, *args):
    return command([exe, *args]).stdout.strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=2)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    toolroot = Path(os.environ["LATEST_TOOLCHAINS"])
    gcc16 = toolroot / "gcc16"
    llvm23 = toolroot / "llvm23"
    compilers = [
        ("gcc14", "/usr/bin/g++-14", "-std=c++26", []),
        ("gcc16", str(gcc16 / "bin/g++"), "-std=c++26", []),
        ("clang18", "/usr/bin/clang++-18", "-std=c++2c", []),
        ("clang23", str(llvm23 / "bin/clang++"), "-std=c++2c",
         ["--gcc-toolchain=" + str(gcc16), "-stdlib=libstdc++"]),
    ]
    expected = {
        "gcc14": "14.", "gcc16": "16.2.", "clang18": "18.",
        "clang23": "23.1.", "rust": "rustc 1.99.1 ",
    }
    configs = []
    versions = {}
    build_records = []
    for label, exe, standard, additional in compilers:
        if not Path(exe).exists():
            raise RuntimeError(f"Expected compiler unavailable: {exe}")
        v = version(exe, "--version").splitlines()[0]
        if expected[label] not in v:
            raise RuntimeError(f"Unexpected {label} version: {v}")
        versions[label] = v
        for opt in (0, 2, 3):
            tag = f"{label}-O{opt}"
            flags = [standard, f"-O{opt}", "-march=x86-64", "-fno-lto", *additional]
            build_cpp(configs, build_records, tag, exe, flags, args.out, required=True)
        if label.startswith("gcc"):
            build_cpp(configs, build_records, f"{label}-O3-hardened", exe,
                      [standard, "-O3", "-march=x86-64", "-fno-lto",
                       "-D_GLIBCXX_ASSERTIONS", *additional], args.out, required=True)
    rustc = str(toolroot / "rust/bin/rustc")
    v = version(rustc, "--version", "--verbose")
    if expected["rust"] not in v:
        raise RuntimeError(f"Wrong Rust toolchain: {v}")
    versions["rust"] = v
    for opt in (0, 2, 3):
        tag = f"rust-O{opt}"
        executable = args.out / tag
        argv = [rustc, "--edition=2024", f"-Copt-level={opt}", "-Ccodegen-units=1",
                "-Clto=off", "-Ctarget-cpu=x86-64",
                str(BENCH / "bench.rs"), "-o", str(executable)]
        command(argv)
        build_records.append({"label": tag, "argv": argv})
        configs.append({"label": tag, "exe": str(executable), "argv": argv})

    # LLVM binary releases may package libc++ and its headers; include a separately
    # identified libc++ variant only if both a compile and a smoke test succeed.
    headers = list(llvm23.glob("include/c++/v1/vector"))
    libpaths = [p for p in (llvm23 / "lib", llvm23 / "lib/x86_64-unknown-linux-gnu",
                           llvm23 / "lib/x86_64-linux-gnu") if p.is_dir()]
    libcxx_files = [f for d in libpaths for f in d.glob("libc++.so*")]
    libcxx_info = {"headers": bool(headers), "libcxx": bool(libcxx_files),
                   "paths": [str(p) for p in libpaths]}
    if headers and libcxx_files:
        libs = [str(p) for p in libpaths]
        flags = ["-std=c++2c", "-stdlib=libc++", "-nostdinc++",
                 "-isystem", str(llvm23 / "include/c++/v1"),
                 "-Wl,-rpath," + ":".join(libs)]
        for libpath in libs:
            flags += ["-L", libpath]
        libcxx_configs = []
        try:
            for opt in (0, 2, 3):
                build_cpp(libcxx_configs, build_records, f"clang23-libcxx-O{opt}",
                          str(llvm23 / "bin/clang++"),
                          [f"-O{opt}", "-march=x86-64", "-fno-lto", *flags],
                          args.out, required=True)
            command([libcxx_configs[2]["exe"], "hash", str(SEEDS[0])], timeout=180)
            configs.extend(libcxx_configs)
            libcxx_info["enabled"] = True
        except Exception as exc:
            libcxx_info["enabled"] = False
            libcxx_info["error"] = str(exc)
            build_records[:] = [r for r in build_records
                                if not r["label"].startswith("clang23-libcxx")]
    else:
        libcxx_info["enabled"] = False

    metadata = {
        "versions": versions, "libcxx": libcxx_info, "configurations": build_records,
        "cpuinfo": next((line for line in Path("/proc/cpuinfo").read_text().splitlines()
                         if line.startswith("model name")), "unknown"),
        "os": platform.platform(), "uname": platform.uname()._asdict(),
        "python": sys.version, "seeds": SEEDS, "tasks": TASKS,
        "trials": args.trials, "warmups": args.warmups,
        "notes": ["single shared GitHub-hosted x86-64 virtual machine",
                  "no hardware isolation; no LTO/PGO; baseline x86-64 target",
                  "sort uses different Rust/C++ standard library algorithms",
                  "elapsed time excludes process launch, includes task setup",
                  "C++ hardened variant measures libstdc++ assertions, not memory safety"],
    }
    (args.out / "metadata.json").write_text(json.dumps(metadata, indent=2))
    print("Versions:", json.dumps(versions, indent=2), flush=True)
    print("libc++:", json.dumps(libcxx_info), flush=True)
    print(f"{len(configs)} compiler configurations", flush=True)
    cases = [(task, seed) for task in TASKS for seed in SEEDS]
    rng = random.Random(20261026)
    checksums, rows = {}, []
    for trial in range(args.warmups + args.trials):
        planned = [(case, config) for case in cases for config in configs]
        rng.shuffle(planned)
        for (task, seed), config in planned:
            stdout = command([config["exe"], task, str(seed)], timeout=180).stdout
            m = re.fullmatch(r"checksum=([0-9a-f]{16})\s+elapsed_ns=(\d+)\s*", stdout)
            if not m:
                raise RuntimeError(f"Bad benchmark output {config['label']}: {stdout!r}")
            checksum, nanos = m.group(1), int(m.group(2))
            key = (task, seed)
            if key in checksums and checksum != checksums[key]:
                raise RuntimeError(f"CHECKSUM MISMATCH {key}: {config['label']} "
                                   f"{checksum} != {checksums[key]}")
            checksums[key] = checksum
            if trial >= args.warmups:
                rows.append({"toolchain": config["label"], "task": task, "seed": seed,
                             "trial": trial - args.warmups + 1,
                             "elapsed_ns": nanos, "checksum": checksum})
        print(f"Completed round {trial+1}/{args.warmups+args.trials}", flush=True)
    with (args.out / "samples.csv").open("w", newline="") as handle:
        w = csv.DictWriter(handle, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    groups = {}
    for row in rows:
        groups.setdefault((row["toolchain"], row["task"]), []).append(row["elapsed_ns"]/1e6)
    summary = [
        {"toolchain": toolchain, "task": task, "median_ms": round(statistics.median(vals), 4),
         "min_ms": round(min(vals), 4), "max_ms": round(max(vals), 4), "n": len(vals)}
        for (toolchain, task), vals in sorted(groups.items())
    ]
    with (args.out / "summary.csv").open("w", newline="") as handle:
        w = csv.DictWriter(handle, fieldnames=list(summary[0]))
        w.writeheader()
        w.writerows(summary)
    (args.out / "checksums.json").write_text(json.dumps(
        {f"{task}|{seed}": checksum for (task, seed), checksum in sorted(checksums.items())}, indent=2))
    print("toolchain,task,median_ms,n", flush=True)
    for row in summary:
        print(f"{row['toolchain']},{row['task']},{row['median_ms']},{row['n']}", flush=True)
    print("All checksums matched", flush=True)

def build_cpp(configs, records, label, compiler, flags, out, required):
    binary = out / label
    argv = [compiler, *flags, str(BENCH / "bench.cpp"), "-o", str(binary)]
    try:
        command(argv)
    except subprocess.CalledProcessError as exc:
        if required:
            raise RuntimeError(f"Compiler build failed {label}: {exc.stderr}") from exc
        return
    records.append({"label": label, "argv": argv})
    configs.append({"label": label, "exe": str(binary), "argv": argv})

if __name__ == "__main__":
    main()
