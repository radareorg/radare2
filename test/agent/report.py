#!/usr/bin/env python3
"""Generate a Markdown table from recorded trials; missing metrics stay n/a."""
import argparse
import collections
import json
import statistics
from pathlib import Path


def load_trials(roots):
    trials = []
    pending = 0
    for root in roots:
        if root.is_file():
            trials.extend(json.loads(line) for line in root.read_text().splitlines() if line.strip())
            continue
        for name in json.loads((root / "manifest.json").read_text()):
            path = root / name / "result.json"
            if not path.exists():
                pending += 1
                continue
            trial = json.loads(path.read_text())
            for key, filename in (("candidate_patch", "candidate.patch"), ("validation_log", "check.log"), ("prompt", "prompt.txt")):
                trial[key] = (path.parent / filename).read_text()
            trials.append(trial)
    return trials, pending


def report(trials, pending=0):
    groups = collections.defaultdict(list)
    for trial in trials:
        groups[(trial["model"], trial["variant"])].append(trial)
    if not groups:
        raise ValueError("No scored trials")
    lines = ["| Model | AGENTS.md | Runs | Functional | Scope | Style probes | API reuse | Valid commit file | Errors/timeouts | Mean seconds | Mean tokens in/out |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for (model, variant), rows in sorted(groups.items()):
        def rate(key):
            return f"{sum(bool(r[key]) for r in rows)}/{len(rows)}"

        def mean(values):
            return f"{statistics.mean(values):.1f}" if len(values) == len(rows) else "n/a"

        elapsed = mean([r["seconds"] for r in rows if isinstance(r.get("seconds"), (int, float))])
        tokens = [mean([r["metrics"][key] for r in rows if isinstance(r["metrics"].get(key), int)])
                  for key in ("prompt_tokens", "completion_tokens")]
        errors = sum(r["status"] != "completed" for r in rows)
        cells = [model, variant, str(len(rows)), rate("functional"), rate("scope"), rate("style"), rate("api"),
                 rate("commit"), str(errors), elapsed, "/".join(tokens)]
        lines.append("| " + " | ".join(c.replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
    lines += ["", "Functional = held-out checks under ASan/UBSan, clean support files and a completed agent run.",
              "Scope additionally rejects unrelated new files; an extra build artifact does not count as a C behavior failure.",
              "Style probes cover whitespace, common call/control spacing, braces and loop declarations; they are not a full style audit.",
              "API reuse and commit files are separate mechanical checks; missing subject files fail. Tokens are provider-reported, never estimated."]
    if pending:
        lines.append(f"Incomplete matrix: {pending} prepared trials have no result; excluded from the table.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="+", type=Path, help="Run directories or exported JSONL files")
    parser.add_argument("--export", type=Path, help="Save records, patches, prompts and check logs as JSONL")
    args = parser.parse_args()
    trials, pending = load_trials(args.results)
    if args.export:
        with args.export.open("x") as stream:
            for trial in trials:
                stream.write(json.dumps(trial) + "\n")
    print(report(trials, pending), end="")
