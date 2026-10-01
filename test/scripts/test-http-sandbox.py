#!/usr/bin/env python3

import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request


def check_http_sandbox(sandbox, **options):
    with tempfile.TemporaryDirectory(prefix="r2-http-sandbox-") as directory:
        check_http_sandbox_in_directory(directory, sandbox, **options)


def check_http_sandbox_in_directory(directory, sandbox, background=False, local_grain="all", local_sandbox=False,
                       http_grain="none", temporary_grain=None, project_tests=False, custom_projects=False):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    executable = os.environ.get("R2", "r2")
    if os.path.dirname(executable):
        executable = os.path.abspath(executable)
    args = [executable, "-N", "-q", "-e", "scr.color=0",
            "-e", "http.bind=127.0.0.1", "-e", f"http.port={port}",
            "-e", f"cfg.sandbox.grain={local_grain}"]
    if custom_projects:
        custom_root = Path(directory) / "custom-projects"
        (custom_root / "existing").mkdir(parents=True)
        (custom_root / "existing" / "rc.r2").write_text("# r2 rdb project file\nf custom_marker=1\n")
        args += ["-e", f"dir.projects={custom_root}"]
    if not sandbox:
        args += ["-e", "http.sandbox=false"]
    if http_grain != "none":
        args += ["-e", f"http.sandbox.grain={http_grain}"]
    if local_sandbox:
        args += ["-c", "e cfg.sandbox=true"]
    start = "=h&" if background else "=h"
    if temporary_grain:
        start += f" @e:http.sandbox.grain={temporary_grain}"
    args += ["-c", start]
    if background:
        args += ["-c", "sleep 30"]
    args += ["-c", "f~HTTP_DEFERRED", "-c", "e cfg.sandbox", "-c", "e cfg.sandbox.grain"]
    if project_tests:
        input_file = Path(directory) / "input.bin"
        input_file.write_bytes(bytes(range(64)))
        args += ["-w", str(input_file)]
    else:
        args += ["-"]
    env = dict(os.environ, R2_NOPLUGINS="1", R2_HTTP_SANDBOX_PROBE="visible", HOME=f"{directory}/home")
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"):
        env[name] = str(Path(directory) / name.lower())
        Path(env[name]).mkdir(mode=0o700)
    expected_files = {entry.name for entry in Path(directory).iterdir()}
    stderr_log = tempfile.TemporaryFile()
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=stderr_log, env=env, cwd=directory)
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request_grain = temporary_grain or http_grain
    scoped = sandbox or local_sandbox

    def permitted(name):
        def includes(grain):
            return grain == "all" or name in grain.split(",")
        return (not sandbox or includes(request_grain)) and (not local_sandbox or includes(local_grain))

    exec_allowed = permitted("exec")
    environ_allowed = permitted("environ")
    local_config = f"{str(local_sandbox).lower()}\n{local_grain}\n".encode()
    http_config = f"{str(sandbox).lower()}\n{request_grain}\n".encode()

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

    def finish():
        stdout, _ = process.communicate(timeout=5)
        stderr_log.seek(0)
        return stdout, stderr_log.read()

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
            assert command(method, "e http.sandbox; e http.sandbox.grain") == http_config

        assert command("GET", ":!!echo HTTP_EXECUTED") == b""
        if scoped:
            for method in ("GET", "POST"):
                for setting in ("http.sandbox=false", "http.sandbox.grain=all", "http.sandbox.grain=none",
                                "cfg.sandbox=false", "cfg.sandbox.grain=none", "cfg.sandbox.grain=all"):
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
                assert command(method, "e http.sandbox; e http.sandbox.grain") == http_config
            for text in ("e http.sandbox.grain=all", "e cfg.sandbox.grain=all", "e cfg.sandbox=false", "e-",
                         "&:f HTTP_DEFERRED", "& f HTTP_DEFERRED"):
                assert command("GET", ":" + text) == b""
            assert (b"HTTP_EXECUTED" in command("GET", "!!echo HTTP_EXECUTED")) == exec_allowed
            assert command("GET", "e cfg.sandbox; e cfg.sandbox.grain") == local_config
            assert command("GET", "e http.sandbox; e http.sandbox.grain") == http_config
            if background and permitted("network"):
                command("POST", "=h--")
                command("GET", "=h-")
        assert command("GET", "?e still-running") == b"still-running\n"
        if project_tests:
            check_http_projects(command, Path(directory), args[0], env)
        if custom_projects:
            assert command("GET", "e dir.projects") == f"{custom_root}\n".encode()
            assert json.loads(command("GET", "Plj")) == ["existing"]
            command("POST", "P existing; Ps custom_saved")
            assert command("GET", "?v custom_marker") == b"0x1\n"
            assert (custom_root / "custom_saved" / "rc.r2").exists()
            assert sorted(json.loads(command("GET", "Plj"))) == ["custom_saved", "existing"]
            command("POST", f"e dir.projects={directory}; Ps still_confined")
            assert command("GET", "e dir.projects") == f"{custom_root}\n".encode()
            assert (custom_root / "still_confined" / "rc.r2").exists()
            assert not (Path(directory) / "still_confined").exists()
        if background and scoped:
            output = command("POST", "e log.cons=true; e http.sandbox=false; e log.cons=false")
            assert b"Key 'http.sandbox' is readonly" in output, output
            assert command("GET", "e log.cons") == b"false\n"
        if not background and (not local_sandbox or local_grain == "all" or "exec" in local_grain.split(",")):
            command("GET", "=h--")
            stdout, stderr = finish()
            assert stdout.endswith(local_config), (stdout, stderr)
            assert process.returncode == 0, stderr
        else:
            process.terminate()
            stdout, stderr = finish()
        assert (b"HTTP_EXECUTED" in stdout) == exec_allowed, (stdout, stderr)
        assert b"HTTP_DEFERRED" not in stdout, (stdout, stderr)
        unexpected_files = {entry.name for entry in Path(directory).iterdir()} - expected_files
        assert not unexpected_files, unexpected_files
    except Exception as error:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, stderr = finish()
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = finish()
        raise AssertionError(f"{error}\nserver returncode={process.returncode}\n"
                             f"stdout={stdout!r}\nstderr={stderr.decode(errors='replace')}") from error
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=5)
        stderr_log.close()
    print(f"PASS http.sandbox={sandbox}, grain={request_grain}, background={background}, "
          f"local_sandbox={local_sandbox}, local_grain={local_grain}, temporary_grain={temporary_grain}")


def check_http_projects(command, directory, r2, env):
    projects = Path(env["XDG_DATA_HOME"]) / "radare2" / "projects"
    outside = projects.parent / "projects_extra"
    outside.mkdir()
    secret = outside / "secret"
    secret.write_bytes(b"PROJECT_OUTSIDE_SECRET\n")
    outside_script = outside / "rc.r2"
    outside_script.write_text("# r2 rdb project file\nf outside_marker=0x99\n")
    original_script = outside_script.read_bytes()
    descriptors = command("GET", "oj")
    maps = command("GET", "omj")
    data = command("GET", "p8 16")

    def unchanged_binary():
        assert command("GET", "oj") == descriptors
        assert command("GET", "omj") == maps
        assert command("GET", "p8 16") == data

    command("GET", "f project_marker=0x2a")
    assert command("GET", "e prj.new") == b"false\n"
    assert command("POST", "?e prefix;Ps sample") == b"prefix\n"
    script = projects / "sample" / "rc.r2"
    assert script.read_bytes().startswith(b"# r2 rdb project file\n")
    assert b"'e prj.name = sample\n" in script.read_bytes()
    for _ in range(3):
        assert json.loads(command("GET", "Plj")) == ["sample"]
    command("POST", "f-project_marker; e prj.sandbox=true; P sample; e prj.sandbox=false")
    assert command("GET", "?v project_marker") == b"0x2a\n"
    unchanged_binary()
    local = subprocess.run([r2, "-N", "-q", "-e", "scr.color=0", "-e", "scr.interactive=false",
                            "-c", "P sample", "-c", "?v project_marker",
                            "-c", "p8 16", "-c", "o.", "-"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=directory, timeout=10)
    assert local.returncode == 0, local.stderr
    assert local.stdout == b"0x2a\n" + data + f"{directory / 'input.bin'}\n".encode(), (local.stdout, local.stderr)

    binary_project = projects / "sample" / "prj.bin"
    command("POST", "e prj.new=true; Ps sample")
    assert not binary_project.exists()
    binary_project.write_bytes(b"invalid binary project must be ignored\n")
    command("POST", "f-project_marker; P sample")
    assert command("GET", "?v project_marker") == b"0x2a\n"
    command("POST", "Ps sample; e prj.new=false")
    assert binary_project.read_bytes() == b"invalid binary project must be ignored\n"
    unchanged_binary()

    inside = projects / "allowed"
    command("POST", f"wtf {inside} 16")
    assert inside.read_bytes() == bytes.fromhex(data.decode())
    assert command("GET", f"cat {script}").startswith(b"# r2 rdb project file\n")
    assert command("GET", f"cat {secret}") == b""
    assert command("GET", f"cat {projects / '..' / 'projects_extra' / 'secret'}") == b""
    command("POST", f"PS {outside / 'dump.r2'}")
    command("POST", f"?e forbidden > {outside / 'write'}")
    assert not (outside / "dump.r2").exists()
    assert not (outside / "write").exists()
    command("POST", f"e dir.projects={outside}")
    assert command("GET", "e dir.projects") == f"{projects}\n".encode()

    for name in ("../projects_extra", "sample/../../projects_extra", str(outside_script)):
        command("POST", "Ps " + name)
        command("GET", "P " + name)
        actual_name = command("GET", "e prj.name")
        assert actual_name == b"sample\n", (name, actual_name)
        assert command("GET", "f~outside_marker") == b""
        unchanged_binary()
    command("POST", "f-project_marker; P " + str(script))
    assert command("GET", "e prj.name") == b"sample\n"
    assert command("GET", "?v project_marker") == b"0x2a\n"
    unchanged_binary()

    (projects / "linked").symlink_to(outside, target_is_directory=True)
    for name in ("linked_script", "hardlinked", "fifo"):
        (projects / name).mkdir()
    (projects / "linked_script" / "rc.r2").symlink_to(outside_script)
    os.link(outside_script, projects / "hardlinked" / "rc.r2")
    os.mkfifo(projects / "fifo" / "rc.r2")
    for name in ("linked", "linked_script", "hardlinked", "fifo"):
        assert command("GET", f"cat {projects / name / 'rc.r2'}") == b""
        command("GET", "P " + name)
        assert command("GET", "f~outside_marker") == b""
        assert command("GET", "e prj.name") == b"sample\n"
    assert json.loads(command("GET", "Plj")) == ["sample"]
    for name in ("linked", "linked_script", "hardlinked"):
        command("POST", "Ps " + name)
        assert outside_script.read_bytes() == original_script
    unchanged_binary()

    legacy = projects / "legacy"
    legacy.mkdir()
    (legacy / "rc.r2").write_text(
        "# r2 rdb project file\no--\n"
        f"o {secret}\nom-*\nf legacy_marker=0x66\n"
        "!!echo PROJECT_ESCAPE\ne http.sandbox=false\ne cfg.sandbox=false\n"
        f"e dir.projects={outside}\ncat {secret}\nPS {outside / 'legacy_dump.r2'}\n"
        "&:f escaped_task=0x99\n")
    output = command("POST", "P legacy")
    assert b"PROJECT_ESCAPE" not in output and b"PROJECT_OUTSIDE_SECRET" not in output
    assert command("GET", "?v legacy_marker") == b"0x66\n"
    assert command("GET", "!!echo PROJECT_ESCAPE") == b""
    assert command("GET", "e dir.projects") == f"{projects}\n".encode()
    assert not (outside / "legacy_dump.r2").exists()
    assert outside_script.read_bytes() == original_script
    assert secret.read_bytes() == b"PROJECT_OUTSIDE_SECRET\n"
    unchanged_binary()

    command("POST", "er prj.name; Ps different_name")
    assert not (projects / "different_name" / "rc.r2").exists()
    assert command("GET", "e prj.name") == b"legacy\n"


if __name__ == "__main__":
    check_http_sandbox(True, project_tests=os.name == "posix")
    check_http_sandbox(False)
    check_http_sandbox(True, http_grain="environ", local_grain="disk", custom_projects=os.name == "posix")
    check_http_sandbox(True, http_grain="exec", local_grain="environ")
    check_http_sandbox(True, background=True, project_tests=os.name == "posix")
    if os.name == "posix":
        check_http_sandbox(True, background=True, custom_projects=True)
    check_http_sandbox(True, http_grain="all", local_sandbox=True, local_grain="socket,network,environ")
    check_http_sandbox(False, background=True, local_sandbox=True, local_grain="socket,network,environ")
    check_http_sandbox(True, background=True, temporary_grain="environ")
