#!/usr/bin/env python3
"""Minimal tool-calling adapter for an OpenAI-compatible local model endpoint."""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:11434/v1")
    parser.add_argument("--model", required=True, help="Exact served model name, including quantization if known")
    parser.add_argument("--key-env", default="OPENAI_API_KEY")
    parser.add_argument("--turns", type=int, default=24)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--temperature", type=float, default=0)
    parser.add_argument("--seed", type=int, help="Only use if supported by the server")
    args = parser.parse_args()
    if args.turns < 1 or args.max_tokens < 1:
        parser.error("turns and max-tokens must be positive")
    messages = [{"role": "system", "content": "You are a coding agent. Use the shell tool to inspect, edit and test files in the working directory. Follow the task and repository instructions. Finish with a brief report."},
                {"role": "user", "content": sys.stdin.read()}]
    tools = [{"type": "function", "function": {"name": "shell", "description": "Run a shell command in the working directory.",
              "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"], "additionalProperties": False}}}]
    metrics = dict(model=args.model, adapter="openai-compatible", temperature=args.temperature,
                   seed=args.seed, max_tokens=args.max_tokens, turn_limit=args.turns,
                   model_calls=0, tool_calls=0, prompt_tokens=None, completion_tokens=None)
    trace = Path(os.environ["AGENT_TRACE"])
    start = time.monotonic()
    usage_complete = dict(prompt_tokens=True, completion_tokens=True)

    def log(record):
        with trace.open("a") as stream:
            stream.write(json.dumps(record) + "\n")

    try:
        for _ in range(args.turns):
            payload = dict(model=args.model, messages=messages, tools=tools, stream=False,
                           temperature=args.temperature, max_tokens=args.max_tokens)
            if args.seed is not None:
                payload["seed"] = args.seed
            headers = {"Content-Type": "application/json"}
            if os.environ.get(args.key_env):
                headers["Authorization"] = "Bearer " + os.environ[args.key_env]
            request = urllib.request.Request(args.base_url.rstrip("/") + "/chat/completions",
                                             data=json.dumps(payload).encode(), headers=headers)
            log({"request": payload})
            metrics["model_calls"] += 1
            with urllib.request.urlopen(request, timeout=90) as response:
                data = json.load(response)
            log({"response": data})
            usage = data.get("usage") or {}
            for key in ("prompt_tokens", "completion_tokens"):
                if isinstance(usage.get(key), int) and usage_complete[key]:
                    metrics[key] = (metrics[key] or 0) + usage[key]
                else:
                    usage_complete[key] = False
                    metrics[key] = None
            message = data["choices"][0]["message"]
            messages.append(message)
            calls = message.get("tool_calls") or []
            if not calls:
                print(message.get("content") or "")
                return
            for call in calls:
                metrics["tool_calls"] += 1
                try:
                    if call["function"]["name"] != "shell":
                        raise ValueError("Unknown tool")
                    arguments = json.loads(call["function"]["arguments"])
                    command = arguments["command"]
                    if not isinstance(command, str):
                        raise ValueError("command must be a string")
                except (KeyError, TypeError, ValueError) as error:
                    output = "Tool error: " + str(error)
                else:
                    # All children stay in run.py's process group. A command
                    # timeout ends the adapter; the runner kills that group.
                    result = subprocess.run(["/bin/sh", "-c", command], stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, text=True, timeout=45)
                    output = f"exit_code={result.returncode}\n" + result.stdout
                    if len(output) > 16000:
                        output = output[:16000] + "\n[output truncated]"
                tool_message = {"role": "tool", "tool_call_id": call["id"], "content": output}
                messages.append(tool_message)
                log({"tool": tool_message})
        raise RuntimeError("Model turn limit reached")
    except BaseException:
        metrics["prompt_tokens"] = metrics["completion_tokens"] = None
        raise
    finally:
        metrics["seconds"] = round(time.monotonic() - start, 3)
        Path(os.environ["AGENT_METRICS"]).write_text(json.dumps(metrics, indent=2) + "\n")


if __name__ == "__main__":
    main()
