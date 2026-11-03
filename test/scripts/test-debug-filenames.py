#!/usr/bin/env python3
"""Check native launch/attach selection using only test-owned processes."""

import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile


def debug_info(r2, directory, target):
    process = subprocess.Popen(
        [r2, "-N", "-q", "-e", "scr.color=0", "-c", "dij;q!!", "-d", target],
        cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(os.environ, R2_NOPLUGINS="1"),
        start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=20)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    text = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", stdout).decode()
    records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    assert process.returncode == 0 and len(records) == 1, (text, stderr.decode())
    return records[0]


def main():
    r2 = shutil.which(os.environ.get("R2", "r2"))
    assert r2, "Set R2 to the radare2 executable to test"
    with tempfile.TemporaryDirectory(prefix="r2-debug-filenames-") as directory:
        root = Path(directory)
        source = root / "wait.c"
        source.write_text("#include <unistd.h>\nint main(void) { for (;;) pause(); }\n")
        fixture = root / "wait-control"
        subprocess.run([os.environ.get("CC", "cc"), str(source), "-o", str(fixture)], check=True)
        waiting = subprocess.Popen([str(fixture)])
        try:
            # A regressed parser can select only this test-owned PID.
            for name in (f"{waiting.pid}-control", str(waiting.pid)):
                executable = root / name
                shutil.copy2(fixture, executable)
                info = debug_info(r2, directory, name)
                assert info.get("pid") != waiting.pid, info
                assert Path(info["exe"]).resolve() == executable.resolve(), info
                assert waiting.poll() is None, "The waiting process was selected instead of the file"
                executable.unlink()
                print("PASS: launch", name)
            info = debug_info(r2, directory, str(waiting.pid))
            assert info.get("pid") == waiting.pid, info
            assert Path(info["exe"]).resolve() == fixture.resolve(), info
            print("PASS: attach to a decimal PID when no local file has that name")
        finally:
            if waiting.poll() is None:
                waiting.kill()
            waiting.wait()


if __name__ == "__main__":
    main()
