#!/usr/bin/env python3
"""Run with R2=/path/to/r2 python3 test/scripts/test-r2-rc.py after building."""

import os
from pathlib import Path
import subprocess
import tempfile


R2 = os.environ.get("R2", "r2")


with tempfile.TemporaryDirectory(prefix="r2-rc-") as directory:
    home = Path(directory)
    rc = home / "custom rc"
    env = dict(os.environ, HOME=directory, USERPROFILE=directory,
               R2_RCFILE=str(rc), EDITOR="r2-no-such-editor",
               VISUAL="r2-no-such-editor")

    def run(*args, success=True):
        result = subprocess.run([R2, "-NN", *args], env=env,
                                capture_output=True, timeout=30)
        assert (result.returncode == 0) == success, result.stderr.decode()

    run("-E", "e scr.color=0", "e scr.utf8=false", "e scr.color=0")
    expected = b"e scr.color=0\ne scr.utf8=false\n"
    assert rc.read_bytes() == expected
    run("-E", "e scr.color=0", "e scr.utf8=false")
    assert rc.read_bytes() == expected

    for initial in (b"", b"# existing\n", b"# existing"):
        rc.write_bytes(initial)
        run("-E", "e scr.color=0")
        separator = b"\n" if initial and not initial.endswith(b"\n") else b""
        assert rc.read_bytes() == initial + separator + b"e scr.color=0\n"

    for initial in (b"e scr.color=0", b"e scr.color=0\r\n"):
        rc.write_bytes(initial)
        run("-E", "e scr.color=0")
        assert rc.read_bytes() == initial

    initial = b"# e scr.color=0\ne scr.color=01\ne scr.color=0 suffix\n"
    rc.write_bytes(initial)
    run("-E", "e scr.color=0", "e scr.color=0")
    assert rc.read_bytes() == initial + b"e scr.color=0\n"

    rc.write_bytes(b"")
    run("-E", "echo saved", "-h")
    assert rc.read_bytes() == b"echo saved\n-h\n"
    run("-h", "-E", "echo ignored")
    assert rc.read_bytes() == b"echo saved\n-h\n"

    env.pop("R2_RCFILE")
    run("-E", "e scr.color=0")
    assert (home / ".radare2rc").read_bytes() == b"e scr.color=0\n"
    env["R2_RCFILE"] = str(home / "missing" / "rc")
    run("-E", "e scr.color=0", success=False)

print("radare2 -E rc tests passed")
