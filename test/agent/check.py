#!/usr/bin/env python3
"""Grade candidate edits against trusted fixtures; never trust agent-written tests."""
import difflib
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

from cases import CASES, HEADER, SOURCE, main_source


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(work):
    return {str(p.relative_to(work)): digest(p) for p in sorted(work.rglob("*"))
            if p.is_file() and ".git" not in p.parts and p.name != "smoke"}


def style_errors(text):
    errors = []
    for number, line in enumerate(text.splitlines(), 1):
        code = re.sub(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//.*', '', line)
        if line.rstrip() != line or re.match(r"^ +\S", code):
            errors.append(f"line {number}: whitespace")
        if re.search(r"\bfor\s*\(\s*(?:int|size_t|ut\d+|char)\b", code):
            errors.append(f"line {number}: loop declaration")
        if re.search(r"\b(?:if|for|while|switch)\(", code):
            errors.append(f"line {number}: control spacing")
        if re.match(r"^\s*(?:if|for|while)\s*\(", code):
            depth = 0
            for i in range(code.index("("), len(code)):
                depth += (code[i] == "(") - (code[i] == ")")
                if depth == 0:
                    tail = code[i + 1:].strip()
                    if not tail.startswith("{") and not (code.lstrip().startswith("while") and tail == ";"):
                        errors.append(f"line {number}: braces")
                    break
        if line.startswith("\t") and re.search(r"\b(?:r_\w+|free|malloc|strdup|memcpy)\(", code):
            errors.append(f"line {number}: call spacing")
    return errors


def grade(job):
    job = Path(job).resolve()
    meta = json.loads((job / "meta.json").read_text())
    spec = CASES[meta["case"]]
    work, baseline = job / "work", job / "baseline"
    before, after = snapshot(baseline), snapshot(work)
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    allowed = lambda p: p in (SOURCE, HEADER, "commit-message.txt") or (p.startswith("test/") and not p.endswith(".md"))
    integrity = before == meta["baseline_hashes"] and all(allowed(p) for p in changed if p in before)
    scope = integrity and all(allowed(p) for p in changed)
    candidate = "\n".join((work / p).read_text() if (work / p).is_file() else "" for p in (SOURCE, HEADER))
    style = style_errors(candidate)
    subject_path = work / "commit-message.txt"
    subject = subject_path.read_text().strip() if subject_path.is_file() else ""
    commit = bool(re.fullmatch(r"[A-Z][^\n]* ##" + spec["tag"], subject)
                  and subject.count("##") == 1 and len(subject) < 100
                  and not re.match(r"(?:Added|Fixed|Removed|Changed)\b", subject))
    api = bool(re.search(r"\b" + spec["helper"] + r"\s*\(", candidate))
    if spec["owned"]:
        api = api and all((work / p).is_file() and "R_OWNED" in (work / p).read_text() for p in (SOURCE, HEADER))
    diff = ""
    for path in changed:
        if any(p.is_file() and b"\0" in p.read_bytes() for p in (baseline / path, work / path)):
            diff += f"Binary file changed: {path} (sha256 {after.get(path, 'deleted')})\n"
            continue
        a = (baseline / path).read_text(errors="replace").splitlines(True) if (baseline / path).is_file() else []
        b = (work / path).read_text(errors="replace").splitlines(True) if (work / path).is_file() else []
        diff += "".join(difflib.unified_diff(a, b, fromfile="a/" + path, tofile="b/" + path))
    (job / "candidate.patch").write_text(diff)
    # Compile in a separate clean copy with trusted build rules and held-out
    # checks. Changes to Makefile, helpers or supplied tests cannot fake a pass.
    with tempfile.TemporaryDirectory(prefix="r2-agent-check-") as tmp:
        clean = Path(tmp) / "work"
        shutil.copytree(baseline, clean)
        for path in (SOURCE, HEADER):
            if (work / path).is_file():
                shutil.copyfile(work / path, clean / path)
            else:
                (clean / path).unlink(missing_ok=True)
        (clean / "test/smoke.c").write_text(main_source(spec["check"]))
        asan = os.environ.get("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
        env = dict(os.environ, ASAN_OPTIONS=asan, UBSAN_OPTIONS="halt_on_error=1")
        command = ["make", "check", "CFLAGS=-O1 -g -Wall -Wextra -Werror=implicit-function-declaration -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie"]
        process = subprocess.Popen(command, cwd=clean, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            log, _ = process.communicate(timeout=30)
            passed = process.returncode == 0
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            log, _ = process.communicate()
            log += "\nChecker timeout\n"
            passed = False
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        (job / "check.log").write_text(log)
    metrics_path = job / "metrics.json"
    metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}
    result = dict(meta, functional=passed and integrity and meta["status"] == "completed",
                  behavior=passed, integrity=integrity, scope=scope, style=not style,
                  style_errors=style, api=api, commit=commit, commit_message=subject,
                  changed_files=changed, added=sum(l.startswith("+") and not l.startswith("+++") for l in diff.splitlines()),
                  deleted=sum(l.startswith("-") and not l.startswith("---") for l in diff.splitlines()),
                  metrics=metrics, asan_options=asan)
    (job / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jobs", nargs="+", type=Path)
    args = parser.parse_args()
    for job in args.jobs:
        r = grade(job)
        print(f"{job.name}: functional={r['functional']} style={r['style']} api={r['api']} commit={r['commit']}")
