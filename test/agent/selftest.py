#!/usr/bin/env python3
"""Calibrate the grader with broken fixtures, known repairs and tampered support."""
import json
import shlex
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from cases import CASES, HEADER, SOURCE, task_source
from check import grade, style_errors
from run import execute, prepare


def adapter_checks(job, tmp):
    requests = []

    class Server(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            turn = len(requests)
            if turn < 3:
                arguments = "{broken" if turn == 1 else json.dumps({"command": "printf adapter-ok"})
                message = {"role": "assistant", "content": None, "tool_calls": [
                    {"id": str(turn), "type": "function", "function": {"name": "shell", "arguments": arguments}}]}
            else:
                message = {"role": "assistant", "content": "Finished mock control"}
            usage = {"prompt_tokens": 10}
            if turn != 2:
                usage["completion_tokens"] = 2
            payload = json.dumps({"choices": [{"message": message}], "usage": usage}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Server)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        adapter = Path(__file__).with_name("openai.py")
        command = shlex.join([sys.executable, str(adapter), "--base-url",
                              f"http://127.0.0.1:{server.server_port}/v1", "--model", "mock-control"])
        result = execute(job, command, 10)
        assert result["status"] == "completed"
        assert result["metrics"]["model_calls"] == 3
        assert result["metrics"]["tool_calls"] == 2
        assert result["metrics"]["prompt_tokens"] == 30
        assert result["metrics"]["completion_tokens"] is None
        assert requests[1]["messages"][-1]["content"].startswith("Tool error:")
        assert "adapter-ok" in requests[2]["messages"][-1]["content"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    # A missing executable is a recorded failed attempt, not a lost trial.
    assert execute(job, "/missing-agent-executable", 1)["status"] == "agent_error"
    # The timeout must terminate descendants too, not only the agent process.
    marker = tmp / "survived"
    sleeper = tmp / "sleep.py"
    child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"
    sleeper.write_text("import subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', " + repr(child) + "])\ntime.sleep(10)\n")
    assert execute(job, shlex.join([sys.executable, str(sleeper)]), .2)["status"] == "timeout"
    time.sleep(1)
    assert not marker.exists(), "timed-out agent left a running child"
    print("adapter: malformed arguments, tool loop, usage, launch failure and process-group timeout pass")


def main():
    with tempfile.TemporaryDirectory(prefix="r2-agent-selftest-") as tmp:
        args = SimpleNamespace(source="HEAD", docs="HEAD", variant=["control=HEAD"],
                               out=Path(tmp) / "runs", repeat=1, case=None, model="grader-control",
                               seed=42, timeout=30, agent=None)
        for name in prepare(args):
            job = args.out / name
            meta = json.loads((job / "meta.json").read_text())
            meta["status"] = "completed"
            (job / "meta.json").write_text(json.dumps(meta))
            case = meta["case"]
            assert not grade(job)["functional"], f"broken {case} passed"
            spec = CASES[case]
            (job / "work" / SOURCE).write_text(task_source(case, solution=True))
            signature = spec["signature"].replace("R_API ", "R_API R_OWNED ") if spec["owned"] else spec["signature"]
            (job / "work" / HEADER).write_text("#include <r_util.h>\n" + signature + ";\n")
            (job / "work/commit-message.txt").write_text("Fix the fixture ##" + spec["tag"] + "\n")
            result = grade(job)
            assert all(result[k] for k in ("functional", "style", "api", "commit", "scope")), (case, result, (job / "check.log").read_text())
            (job / "work/Makefile").write_text("check:\n\ttrue\n")
            assert not grade(job)["functional"], "modified build rules passed"
            print(f"{case}: broken fails, reference passes, tampering fails")
        assert style_errors("    if(x) return 0;\n")
        assert not style_errors("\tif (x) {\n\t\treturn 0;\n\t}\n")
        assert not style_errors("\tif (len < sizeof (ut32)) {\n\t\treturn false;\n\t}\n")
        adapter_checks(job, Path(tmp))


if __name__ == "__main__":
    main()
