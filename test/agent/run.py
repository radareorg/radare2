#!/usr/bin/env python3
"""Prepare/run paired agent trials. An adapter reads stdin and edits its cwd."""
import argparse
import json
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path

from cases import CASES, fixture, git
from check import grade, snapshot


def prepare(args):
    source = git("rev-parse", args.source + "^{commit}").strip()
    docs = git("rev-parse", args.docs + "^{commit}").strip()
    jobs = []
    variants = []
    for value in args.variant:
        label, ref = value.split("=", 1)
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", label) or label in [v[0] for v in variants]:
            raise ValueError("Variant labels must be unique simple names")
        variants.append((label, git("rev-parse", ref + "^{commit}").strip()))
    args.out.mkdir(parents=True, exist_ok=False)
    for repeat in range(1, args.repeat + 1):
        for case in args.case or CASES:
            for label, ref in variants:
                name = f"{case}-{label}-{repeat}"
                job = args.out / name
                work = job / "work"
                fixture(work, case, source, docs, ref)
                shutil.copytree(work, job / "baseline")
                subprocess.run(["git", "init", "-q", str(work)], check=True)
                subprocess.run(["git", "-C", str(work), "add", "."], check=True)
                subprocess.run(["git", "-C", str(work), "-c", "user.name=Agent benchmark",
                                "-c", "user.email=benchmark@example.invalid", "commit", "-qm", "Initial fixture"], check=True)
                prompt = ("Work only in the supplied working directory. Read AGENTS.md and relevant\n"
                          "repository references. This is a synthetic radare2 API slice; its root\n"
                          "Makefile builds it without configuring or installing the full project.\n"
                          "Edit libr/util/agent_task.c and libr/include/agent_task.h as needed.\n"
                          "You may add regression tests under test/. Do not change supplied helpers,\n"
                          "build rules or documentation. Run relevant checks. Do not create a git\n"
                          "commit. Write your proposed one-line subject to commit-message.txt.\n\n" + CASES[case]["prompt"] + "\n")
                (job / "prompt.txt").write_text(prompt)
                agents = (work / "AGENTS.md").read_bytes()
                meta = dict(case=case, variant=label, repeat=repeat, model=args.model,
                            source_ref=source, docs_ref=docs, agents_ref=ref,
                            agents_bytes=len(agents), agents_words=len(agents.split()),
                            baseline_hashes=snapshot(work), status="prepared", seed=args.seed,
                            timeout=args.timeout, adapter=args.agent)
                (job / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
                jobs.append(name)
    random.Random(args.seed).shuffle(jobs)
    (args.out / "manifest.json").write_text(json.dumps(jobs, indent=2) + "\n")
    return jobs


def execute(job, command, timeout):
    meta_path = job / "meta.json"
    meta = json.loads(meta_path.read_text())
    start = time.monotonic()
    env = dict(os.environ, AGENT_METRICS=str(job / "metrics.json"), AGENT_TRACE=str(job / "trace.jsonl"))
    with (job / "prompt.txt").open() as stdin, (job / "stdout.txt").open("w") as stdout, (job / "stderr.txt").open("w") as stderr:
        try:
            process = subprocess.Popen(shlex.split(command), cwd=job / "work", env=env,
                                       stdin=stdin, stdout=stdout, stderr=stderr, start_new_session=True)
        except OSError as error:
            stderr.write(str(error) + "\n")
            meta.update(status="agent_error", exit_code=None, seconds=round(time.monotonic() - start, 3))
            meta_path.write_text(json.dumps(meta, indent=2) + "\n")
            return grade(job)
        status = "completed"
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            status = "timeout"
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    meta.update(status=status if code == 0 or status == "timeout" else "agent_error",
                exit_code=code, seconds=round(time.monotonic() - start, 3))
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    return grade(job)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=lambda p: Path(p).resolve())
    parser.add_argument("--source", default="HEAD", help="Fixed source snapshot for all variants")
    parser.add_argument("--docs", default="HEAD", help="Fixed supporting documentation for all variants")
    parser.add_argument("--variant", action="append", required=True, help="label=git-ref; selects AGENTS.md only")
    parser.add_argument("--model", required=True, help="Exact model/version label, for the report")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--case", action="append", choices=CASES)
    parser.add_argument("--seed", type=int, default=42, help="Trial ordering, not a provider sampling seed")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--agent", help="Adapter command (no shell); absent means prepare only")
    args = parser.parse_args()
    if args.repeat < 1 or args.timeout <= 0:
        parser.error("repeat and timeout must be positive")
    jobs = prepare(args)
    for name in jobs:
        if args.agent:
            result = execute(args.out / name, args.agent, args.timeout)
            print(f"{name}: {result['status']} functional={result['functional']}", flush=True)
        else:
            print(args.out / name)


if __name__ == "__main__":
    main()
