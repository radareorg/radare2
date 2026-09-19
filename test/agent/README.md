# Coding agent experiments

Compare AGENTS.md revisions with the same model, task, source helpers and
supporting documentation. Python 3.9+, Git, Make and a C compiler with ASan/UBSan
are required. No Python packages or model SDKs are needed. Run on a disposable
Linux environment: agents execute shell commands; a fresh fixture is not a
security sandbox.

The three deliberately small **synthetic** tasks cover current padding APIs and
ownership annotations, overflow-safe unaligned binary reads, and JSON buffer
lifetime. Helpers and the JSON parser are extracted from a fixed repository
commit. The surrounding API slice/build shims are synthetic. This avoids full
builds, downloads and changes to real radare2 files. Results do not establish
performance on large or historical repository bugs.

## Run a comparison

Start your model server separately. Use its actual model ID (including model
revision/quantization), not the example names below. Record the server version,
hardware, context size and agent configuration with the results.

```sh
python3 test/agent/selftest.py
python3 test/agent/run.py --out /tmp/r2-agent-qwen \
  --source HEAD --docs HEAD --model 'your-exact-model-id' --repeat 3 \
  --variant old=BASE_COMMIT --variant new=PR_COMMIT \
  --agent "python3 $PWD/test/agent/openai.py --base-url http://127.0.0.1:11434/v1 --model your-exact-model-id"
python3 test/agent/report.py /tmp/r2-agent-qwen
```

Use `report.py --export results.jsonl /tmp/r2-agent-qwen` to save a portable
record with prompts, patches and validation logs. `report.py results.jsonl`
recreates its Markdown table. Raw adapter traces stay in the run directories.

`openai.py` works with the tool-calling Chat Completions interface offered by
local servers. The URL and model are explicit; it never downloads weights or
silently substitutes a model. For a server requiring authentication, set
`OPENAI_API_KEY` or choose another variable with `--key-env`. Authorization
headers are not saved. The default is temperature 0, 24 model turns, 4096 output
tokens per turn and one simple shell tool. `--seed` is optional because not all
servers accept it. The runner's separate `--seed` only randomizes trial order.

Other coding agents can be wrapped by any executable that reads its task from
stdin, edits the current directory and exits. Pass its command in `--agent`;
arguments are parsed without a shell. Configure the same tools, reasoning,
approvals and budgets for every variant. Start a fresh process/context per trial;
disable cross-trial memories and global instruction files where supported.
An adapter can optionally write numeric `prompt_tokens`, `completion_tokens`,
`model_calls` and `tool_calls` to `$AGENT_METRICS` as JSON. Missing values remain
`n/a`. Tool-call failures and model timeouts must not be retried selectively.

Omit `--agent` to prepare trials for an external agent controller. The shuffled
order is in `manifest.json`; each trial has `prompt.txt` and a `work/` directory.
The controller must record `status` (`completed`, `timeout` or `agent_error`),
`exit_code`, elapsed `seconds` and its actual configuration in `meta.json`, then
run `python3 test/agent/check.py /absolute/path/to/trial`. Do not mark failed or
interrupted agents as completed. Keep the controller, grader, other trials and
reference solutions outside the agent's allowed workspace.

## What is measured

- `--source` freezes helper implementations; `--docs` freezes supporting docs.
  Only AGENTS.md varies. All refs resolve to full commit IDs before execution.
- Each `(task, variant, repeat)` starts with an independent Git fixture. The
  runner records initial file hashes, prompt, full patch, validation log,
  stdout/stderr, configuration, exit status and elapsed time. The bundled
  adapter also records requests/responses/tool results and provider usage.
- Functional success requires a completed agent run, unchanged support files,
  and held-out behavioral tests under ASan/UBSan. The evaluator rebuilds from
  trusted originals with only candidate source/header edits. Modified tests or
  Makefiles cannot manufacture a pass. Added regression tests are retained but
  are not graded for quality. A separate scope check reports unrelated added
  files, including leftover build artifacts, without calling them C failures.
- Separate style probes check tabs/trailing whitespace, common call/control
  spacing, braces and loop declarations. API reuse checks the expected helper
  and ownership annotations. Neither is a complete semantic/style audit.
- Commit subjects are checked for a capitalized first character, one line under
  100 characters, no common past-tense opening, and exactly one expected final
  tag (`##util` or `##crash`). This mechanical proxy does not grade prose quality
  or actual Git commit creation.
- Report every attempt, including failures. Use repetitions and retain paired
  task results; a few easy tasks or a timing difference are not evidence of
  general improvement. Do not compare model latency across different hardware,
  adapters or concurrent loads. Review traces before attributing a failure to
  instruction text. Record any guidance change made after observing results.

`selftest.py` verifies that broken fixtures fail, known repairs pass and changed
support files fail. If LeakSanitizer is unavailable (for example under ptrace),
use `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1` and report that limitation.
Address and undefined-behavior checks remain enabled; leak freedom is then not
measured. On another platform, adapt the compiler/sanitizer flags explicitly.

To add a task, extend `CASES` in `cases.py` with the user prompt, initial code,
signature, public smoke check, held-out edge cases and a reference repair. Run
the calibration before collecting results. Keep grading rules fixed for the
whole comparison; correct grader bugs consistently across all saved trials.
