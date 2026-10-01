#!/usr/bin/env python3

import json
import os
import socket
import subprocess
import time
import urllib.parse
import urllib.request


def check_http_sandbox(sandbox, background=False, local_grain="all", local_sandbox=False):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    args = [os.environ.get("R2", "r2"), "-N", "-q", "-e", "scr.color=0",
            "-e", "http.bind=127.0.0.1", "-e", f"http.port={port}",
            "-e", f"cfg.sandbox.grain={local_grain}"]
    if not sandbox:
        args += ["-e", "http.sandbox=false"]
    if local_sandbox:
        args += ["-c", "e cfg.sandbox=true"]
    start = "=h&" if background else "=h"
    args += ["-c", start]
    if background:
        args += ["-c", "sleep 30"]
    args += ["-c", "f~HTTP_DEFERRED", "-c", "e cfg.sandbox",
             "-c", "e cfg.sandbox.grain", "-"]
    env = dict(os.environ, R2_NOPLUGINS="1", R2_HTTP_SANDBOX_PROBE="visible")
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    scoped = sandbox or local_sandbox

    def permitted(name):
        return not sandbox and (not local_sandbox or local_grain == "all" or name in local_grain.split(","))

    exec_allowed = permitted("exec")
    environ_allowed = permitted("environ")
    local_config = f"{str(local_sandbox).lower()}\n{local_grain}\n".encode()
    http_config = f"{str(sandbox).lower()}\n".encode()

    def command(method, text):
        url = base + "/cmd/"
        data = None
        if method == "GET":
            url += urllib.parse.quote(text, safe="")
        else:
            data = text.encode()
        request = urllib.request.Request(url, data=data, method=method)
        with opener.open(request, timeout=5) as response:
            return response.read()

    try:
        for attempt in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if process.poll() is not None:
                    raise AssertionError("HTTP server exited before listening")
                time.sleep(0.05)
        else:
            raise AssertionError("HTTP server did not start")

        for method in ("GET", "POST"):
            assert command(method, "?e ordinary") == b"ordinary\n"
            assert command(method, "echo $(echo nested)") == b"nested\n"
            assert command(method, "wx 90c3; p8 2") == b"90c3\n"
            assert (b"HTTP_EXECUTED" in command(method, "!echo HTTP_EXECUTED")) == (not scoped)
            for text in ("!!echo HTTP_EXECUTED", "?e input | echo HTTP_EXECUTED", ".!echo ?e HTTP_EXECUTED"):
                result = command(method, text)
                assert (b"HTTP_EXECUTED" in result) == exec_allowed, (method, text, result)
            count = command(method, "%R2_HTTP_SANDBOX_PROBE~?")
            assert count == (b"1\n" if environ_allowed else b"0\n"), count
            assert command(method, "e cfg.sandbox; e cfg.sandbox.grain") == local_config
            assert command(method, "e http.sandbox") == http_config

        assert command("GET", ":!!echo HTTP_EXECUTED") == b""
        if scoped:
            for method in ("GET", "POST"):
                for setting in ("http.sandbox=false", "cfg.sandbox=false", "cfg.sandbox.grain=none", "cfg.sandbox.grain=all"):
                    command(method, "e " + setting)
                command(method, "e-")
                tasks = {task["id"] for task in json.loads(command(method, "&j"))}
                for text in ("&:f HTTP_DEFERRED", "& f HTTP_DEFERRED",
                             "&t f HTTP_DEFERRED", "bg f HTTP_DEFERRED", "T=&", "T=&&"):
                    assert b"HTTP_DEFERRED" not in command(method, text)
                assert {task["id"] for task in json.loads(command(method, "&j"))} == tasks
                assert command(method, "f~HTTP_DEFERRED") == b""
                assert (b"HTTP_EXECUTED" in command(method, "!!echo HTTP_EXECUTED")) == exec_allowed
                assert command(method, "%R2_HTTP_SANDBOX_PROBE~?") == (b"1\n" if environ_allowed else b"0\n")
                assert command(method, "e cfg.sandbox; e cfg.sandbox.grain") == local_config
                assert command(method, "e http.sandbox") == http_config
            for text in ("e cfg.sandbox.grain=all", "e cfg.sandbox=false", "e-",
                         "&:f HTTP_DEFERRED", "& f HTTP_DEFERRED"):
                assert command("GET", ":" + text) == b""
            assert (b"HTTP_EXECUTED" in command("GET", "!!echo HTTP_EXECUTED")) == exec_allowed
            assert command("GET", "e cfg.sandbox; e cfg.sandbox.grain") == local_config
            assert command("GET", "e http.sandbox") == http_config
            if background and permitted("network"):
                command("POST", "=h--")
                command("GET", "=h-")
        assert command("GET", "?e still-running") == b"still-running\n"
        if not background and (not local_sandbox or local_grain == "all" or "exec" in local_grain.split(",")):
            command("GET", "=h--")
            stdout, stderr = process.communicate(timeout=5)
            assert stdout.endswith(local_config), (stdout, stderr)
            assert process.returncode == 0, stderr
        else:
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
        assert (b"HTTP_EXECUTED" in stdout) == exec_allowed, (stdout, stderr)
        assert b"HTTP_DEFERRED" not in stdout, (stdout, stderr)
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)
    print(f"PASS http.sandbox={sandbox}, background={background}, "
          f"local_sandbox={local_sandbox}, local_grain={local_grain}")


if __name__ == "__main__":
    check_http_sandbox(True)
    check_http_sandbox(False)
    check_http_sandbox(True, background=True)
    check_http_sandbox(True, local_sandbox=True, local_grain="socket,network,environ")
    check_http_sandbox(False, background=True, local_sandbox=True, local_grain="socket,network,environ")
