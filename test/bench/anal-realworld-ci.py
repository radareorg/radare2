#!/usr/bin/env python3
import csv
import json
import os
from pathlib import Path
import random
import shutil
import shlex
import statistics
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve()
results = root / "results"
results.mkdir(exist_ok=True)
cases = {"ls": "elf/ls", "pigz": "elf/pigz", "libc": "elf/libc-2.27.so", "Mastodon": "mach0/Mastodon"}
installs = {}
metadata = {"platform": os.uname()._asdict() if hasattr(os.uname(), "_asdict") else list(os.uname()),
            "compiler": subprocess.check_output(["cc", "--version"], text=True).strip()}
for variant in ["candidate", "baseline", "fixtures"]:
    metadata[variant] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root / variant, text=True).strip()
(results / "environment.json").write_text(json.dumps(metadata, indent=2))
print("ENVIRONMENT " + json.dumps(metadata), flush=True)

def run(args, cwd, log, env=None):
    with (results / log).open("w") as out:
        proc = subprocess.run(list(map(str, args)), cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT)
    if proc.returncode:
        print((results / log).read_text()[-16000:], flush=True)
        raise RuntimeError((args, proc.returncode))

for variant in ["candidate", "baseline"]:
    src = root / variant
    prefix = src / "_install"
    installs[variant] = prefix
    if variant == "baseline":
        for name in ["sdb", "qjs", "otezip", "capstone-v5", "zydis"]:
            dep = root / "candidate/subprojects" / name
            if dep.exists():
                shutil.copytree(dep, src / "subprojects" / name, dirs_exist_ok=True, symlinks=True)
        shutil.copyfile(root / "candidate/test/bench/anal-layout.c", src / "test/bench/anal-layout.c")
    run(["./configure", "--prefix=" + str(prefix), "CFLAGS=-O2"], src, variant + "-configure.log")
    run(["make", "-j3"], src, variant + "-build.log")
    run(["make", "install"], src, variant + "-install.log")
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "r_core"], text=True,
        env=dict(os.environ, PKG_CONFIG_PATH=str(prefix / "lib/pkgconfig"))))
    run(["cc", "-O2", "-I" + str(src / "libr/include"), "-I" + str(src / "subprojects/sdb/include"),
         src / "test/bench/anal-layout.c", "-o", results / (variant + "-bench"),
         *flags],
        src, variant + "-bench-build.log")

def environment(variant):
    prefix = installs[variant]
    return dict(os.environ, PATH=str(prefix / "bin") + os.pathsep + os.environ["PATH"],
                LD_LIBRARY_PATH=str(prefix / "lib"), DYLD_LIBRARY_PATH=str(prefix / "lib"),
                R2_NOPLUGINS="1", R2_LOG_LEVEL="0", XDG_DATA_HOME=str(results / "test-data"),
                XDG_CACHE_HOME=str(results / "test-cache"))

src = root / "candidate"
(src / "test/bins").symlink_to(root / "fixtures")
test_env = environment("candidate")
test_env.pop("R2_LOG_LEVEL", None)
units = ["test_vec", "test_anal_block", "test_anal_function", "test_anal_var", "test_io"]
run(["make", "-C", "test/unit", "-j3", *["bin/" + n for n in units]], src, "unit-build.log")
for name in units:
    run([src / "test/unit/bin" / name], src / "test", name + ".log", test_env)
run([installs["candidate"] / "bin/r2r", "-C", "test", "db/cmd/cmd_agf", "db/anal/java",
     "db/anal/emu", "db/anal/x86_64", "db/cmd/cmd_af", "db/cmd/cmd_afb",
     "db/cmd/cmd_afl", "db/cmd/cmd_afv", "db/cmd/cmd_graph", "db/anal/vars", "db/anal/xrefs",
     "db/cmd/projects", "db/anal/arm64", "db/anal/mips", "db/anal/x86_overlapping",
     "db/cmd/cmd_pdc", "db/cmd/cmd_pdc_opt", "db/cmd/cmd_pdc_inline",
     "db/cmd/cmd_pdc_ast", "db/io"], src, "r2r.log", test_env)

print("REGRESSIONS PASSED: " + ", ".join(units) + " and selected r2r suites", flush=True)
rows = []
rng = random.Random(27286)
workloads = [(name, "aaa") for name in cases] + [("ls", "aaaa"), ("pigz", "aaaa")]
for trial in range(4):
    for name, command in workloads:
        variants = ["baseline", "candidate"]
        rng.shuffle(variants)
        for variant in variants:
            start = time.monotonic()
            proc = subprocess.run([results / (variant + "-bench"), root / "fixtures" / cases[name], command],
                                  env=environment(variant), capture_output=True, text=True, check=True)
            row = json.loads(proc.stdout)
            row.update(variant=variant, case=name, command=command, trial=trial,
                       warmup=trial == 0, wall_s=time.monotonic() - start)
            rows.append(row)
            with (results / "realworld-runs.jsonl").open("a") as out:
                out.write(json.dumps(row) + "\n")
            print("RESULT " + json.dumps(row), flush=True)

for name, command in workloads:
    identity = {(r["functions"], r["blocks"], r["memberships"], r["checksum"])
                for r in rows if r["case"] == name and r["command"] == command}
    if len(identity) != 1:
        raise RuntimeError(("analysis output changed", name, command, identity))

summary = []
for name, command in workloads:
    for variant in ["baseline", "candidate"]:
        selected = [r for r in rows if r["case"] == name and r["command"] == command
                    and r["variant"] == variant and not r["warmup"]]
        row = dict(case=name, command=command, variant=variant, runs=len(selected))
        for key in ["cpu_s", "wall_s", "function_owned_bytes", "function_allocations", "heap_in_use", "peak_rss"]:
            values = [r[key] for r in selected]
            row[key] = statistics.median(values)
            row[key + "_min"] = min(values)
            row[key + "_max"] = max(values)
        summary.append(row)
        print("SUMMARY " + json.dumps(row), flush=True)
(results / "realworld-summary.json").write_text(json.dumps(summary, indent=2))
with (results / "realworld-summary.csv").open("w") as out:
    writer = csv.DictWriter(out, fieldnames=list(summary[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(summary)
with (results / "realworld-runs.csv").open("w") as out:
    writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
