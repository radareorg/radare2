# PR 26750: hosted Luna pilot

These are **30 actual independent `gpt-5.6-luna` agent runs**, two repetitions
of each of the three synthetic tasks for each guidance variant. They are hosted
ChatGPT Work agents, not a local model benchmark. Qwen, Gemma and other local
models were not available in this environment and were not run.

| AGENTS.md variant | Commit | Lines / words / bytes | Functional | Scope | Style probes | API reuse | Valid commit file |
|---|---|---:|---:|---:|---:|---:|---:|
| Before PR | `dd5327e` | 111 / 780 / 5216 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 |
| Original PR | `b60badf` | 54 / 562 / 4167 | 6/6 | 5/6 | 6/6 | 6/6 | 4/6 |
| Link-only experiment | `b9b5e59` | 53 / 550 / 4168 | 6/6 | 6/6 | 6/6 | 6/6 | 0/6 |
| Short inline reminder | `2530906` | 55 / 567 / 4271 | 6/6 | 6/6 | 6/6 | 6/6 | 4/6 |
| Final, explicit user-visible rule | `da8a0e1` | 55 / 570 / 4289 | 6/6 | 6/6 | 6/6 | 6/6 | 5/6 |

The original PR and short-inline variant omitted `##util` on both padding
trials. Link-only guidance produced no conforming subject files. In the final
variant, all five written subjects conform; the remaining JSON trial supplied
a conforming subject in its final chat report but did not create the required
`commit-message.txt`. It remains a failure of the requested deliverable. The
original PR's scope failure is an extra `check_agent_json` binary, not a C
behavior failure. Candidate code was not repaired after the trials.

This pilot supports retaining critical rules inline and clarifying when tags
are required. It does **not** demonstrate improved coding accuracy: every
variant passed these easy tasks, and the old guidance achieved the best commit
file score. The final instructions are 50% fewer lines, 27% fewer words and 18%
fewer bytes than the original. Word/byte counts are not model token counts.

## Method and limitations

- Source helpers were fixed at `dd5327e42a414d4a1d554563575a1e985ebe58c7` and
  supporting docs at `b9b5e5953adffbda67a26b668e24e8500445e17f` for every run.
  Only AGENTS.md varied. The later Linux path clarification in DEVELOPERS.md
  was deliberately not added to any arm's frozen supporting docs.
- Each agent had a fresh context (`fork_turns=none`) and a separate Git fixture.
  All used the same hosted runtime settings. The model's sampling seed, exact
  backend build, reasoning budget, token counts, costs and hardware were not
  exposed. Consequently those metrics are unavailable, not estimated.
- Trials were dispatched in seeded order, up to six concurrently, with the
  same 300-second instruction. This hosted limit was requested, not enforced
  by the CLI runner. All completed within it. Recorded seconds run from batch
  dispatch to the agent's completion marker, include controller delay and
  concurrent load, and must not be interpreted as a speed comparison.
- The first matrix contained old/original/link-only. After observing missing
  tags, two further six-trial variants refined the wording. All intermediate
  results are included. This is an exploratory, adaptive pilot, not an
  independent held-out validation of the chosen final wording.
- The grader compiled candidates against fresh trusted support files and
  separate behavioral checks with ASan/UBSan. LeakSanitizer fails under this
  environment's tracing, so all trials used
  `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`. Leak freedom was not measured.
- A braces probe initially misread nested `sizeof (...)` conditions. It was
  corrected and applied to every saved candidate. Behavior and scope are
  reported separately so a leftover test executable is not mislabeled as a
  functional failure. No agent retry or candidate edit was used to improve
  a recorded score.
- Style/API/commit checks are mechanical proxies. No full radare2 build,
  r2r integration task, long-running analysis task or test-quality scoring was
  attempted. Two repetitions per small task do not support general claims
  about model quality or statistical significance.

The JSONL records preserve per-trial refs, original file hashes, task prompts,
candidate patches, checker logs, delivered subject, checks and observed timing.
Hosted tool transcripts and provider usage were not exported by this adapter;
the local endpoint adapter records its own traces for future runs.

Regenerate the full measured table:

```sh
python3 test/agent/report.py test/agent/results/pr26750-luna.jsonl
```

Prepare the same task/guidance matrix for another controller, or add `--agent`
with a command from the parent README to run a local model:

```sh
python3 test/agent/run.py --out /tmp/r2-agent-reproduction \
  --source dd5327e --docs b9b5e59 --model YOUR_EXACT_MODEL_ID --repeat 2 \
  --variant old=dd5327e --variant pr=b60badf --variant link_only=b9b5e59 \
  --variant inline_short=2530906 --variant final=da8a0e1
```

The fixture and grading can be reproduced; nondeterministic hosted model
responses and timings cannot be promised to reproduce.

The JSONL tested_*_ref fields retain the local trial commits. The main
*_ref fields identify published commits with identical Git trees; changed
SHAs reflect commit metadata only. The tree hashes were verified at publication.
