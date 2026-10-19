#!/usr/bin/env python3

import base64
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import threading
import time


def envelope(body=b"hello m\xc3\xb3n\x00end", status=200):
    return json.dumps({"status": status, "body": base64.b64encode(body).decode(),
                       "encoding": "base64"}).encode()


class FilesystemXHR:
    """Model TinyEMU's .fscmd boundary using a regular file and a worker."""

    def __init__(self, root, reply, completion, delay, reply_size):
        self.root = root
        self.reply = reply
        self.completion = completion
        self.delay = delay
        self.reply_size = reply_size
        self.request = None
        self.error = None
        self.stop = threading.Event()
        (root / "tmp").mkdir()
        (root / ".fscmd").touch()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.wait(0.005):
                command = (self.root / ".fscmd").read_bytes()
                if not command.endswith(b"\n"):
                    continue
                fields = shlex.split(command.decode())
                assert len(fields) == 8 and fields[0] == "xhr", fields
                assert fields[1] == "https://relay.invalid/http.php?guest=1", fields
                assert fields[2:4] == ["", ""] and fields[6:] == ["", "0"], fields
                paths = [self.root / name for name in fields[4:6]]
                for path, name in zip(paths, ["request", "reply"]):
                    assert path.name == name and path.parent.parent == self.root / "tmp", path
                    assert path.parent.name.startswith("r2-http-"), path
                    assert path.parent.stat().st_mode & 0o777 == 0o700
                self.request = json.loads(paths[0].read_bytes())
                assert self.request["token"] == 'test-token-"\\secret'
                assert b"test-token" not in command
                if self.completion is None or self.stop.wait(self.delay):
                    return
                if self.reply is not None:
                    paths[1].write_bytes(self.reply)
                    if self.reply_size:
                        with paths[1].open("r+b") as output:
                            output.truncate(self.reply_size)
                with (self.root / ".fscmd").open("r+b") as control:
                    control.seek(len(command))
                    control.write(self.completion)
                return
        except Exception as error:
            self.error = error

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()
        if self.error:
            raise self.error


def main():
    root = Path(__file__).resolve().parents[2]
    executable = os.environ.get("R2", str(root / "binr/radare2/radare2"))
    failure = {"error": "HTTP request failed or denied"}

    def request(method="GET", url="https://provider.invalid/v1/models", headers="",
                data=None, reply=envelope(), completion=struct.pack("<i", 0),
                delay=0, reply_size=0, env=None, setup="", data_js=None,
                summary=False):
        with tempfile.TemporaryDirectory(prefix="r2-guest-http-") as temporary:
            # The command must use paths relative to the 9p root, even if its mount contains spaces.
            mount = Path(temporary) / 'shared fs "quote"'
            mount.mkdir()
            worker = FilesystemXHR(mount, reply, completion, delay, reply_size)
            settings = dict(os.environ, R2_HTTP_RELAY="https://relay.invalid/http.php?guest=1",
                            R2_HTTP_UPSTREAM="https://provider.invalid/v1",
                            R2_HTTP_TOKEN='test-token-"\\secret', R2_HTTP_FS=str(mount),
                            R2_HTTP_TIMEOUT="1", R2_CURL="1")
            settings.update(env or {})
            args = [json.dumps(arg) for arg in [method, url, headers]]
            if data_js is not None:
                args.append(data_js)
            elif data is not None:
                args.append(json.dumps(data))
            result_js = "{status: result.status, size: result.body.length}" if summary else "result"
            script = setup + "try { const result = r2.http(" + ",".join(args) + ");"
            script += "console.log(JSON.stringify(" + result_js + ")); }"
            script += "catch (e) { console.log(JSON.stringify({error: e.message})); }"
            try:
                result = subprocess.run([executable, "-NNq", "-e", "scr.color=0",
                                         "-e", "log.level=0", "-c", "'js " + script,
                                         "-c", "q", "-"], env=settings, capture_output=True,
                                        text=True, timeout=10, check=True)
            finally:
                worker.close()
            assert not result.stderr, result.stderr
            assert not list((mount / "tmp").iterdir()), "temporary request files leaked"
            return json.loads(result.stdout), worker.request

    result, sent = request(delay=0.05)
    assert result == {"status": 200, "body": "hello món\x00end"}, result
    assert sent == {"token": 'test-token-"\\secret', "method": "GET", "path": "/models",
                    "headers": "", "data": ""}, sent
    data = json.dumps({"prompt": 'hello món\n"quoted"'}, ensure_ascii=False)
    headers = "Content-Type: application/json\nAuthorization: Bearer test"
    result, sent = request("POST", headers=headers, data=data, reply=envelope(data.encode(), 201))
    assert result == {"status": 201, "body": data}, result
    assert sent["headers"] == headers + "\n" and sent["data"] == data
    assert sent["method"] == "POST"
    assert request("POST", reply=envelope(b"", 204))[0] == {"status": 204, "body": ""}
    for status in [302, 401, 404, 429, 500]:
        assert request(reply=envelope(b"upstream error", status))[0] == {
            "status": status, "body": "upstream error"}
    for url, path in [("https://provider.invalid/v1", "/"),
                      ("https://provider.invalid/v1?list=1", "/?list=1"),
                      ("https://provider.invalid/v1/models?name=a%2Fb", "/models?name=a%2Fb")]:
        assert request(url=url)[1]["path"] == path
    assert request(env={"R2_HTTP_UPSTREAM": "https://provider.invalid/v1/"})[1]["path"] == "/models"

    for url in ["https://other.invalid/v1/models", "https://provider.invalid/v10/models",
                "https://provider.invalid/v", "file:///v1/models", "https://user@provider.invalid/v1",
                "https://provider.invalid/v1/#fragment", "https://provider.invalid/v1/\ninvalid"]:
        result, sent = request(url=url)
        assert result == failure and sent is None, (url, result, sent)
    for env in [{"R2_HTTP_TOKEN": ""}, {"R2_HTTP_UPSTREAM": ""},
                {"R2_HTTP_UPSTREAM": "https://provider.invalid/v1?bad=1"},
                {"R2_HTTP_RELAY": 'https://relay.invalid/"bad'},
                {"R2_HTTP_RELAY": "https://relay.invalid/" + "x" * 1024},
                {"R2_HTTP_FS": "/nonexistent-r2-http-mount"}]:
        result, sent = request(env=env)
        assert result == failure and sent is None, (env, result)
    for grain in ["none", "socket", "network", "socket,network", "all"]:
        setup = 'r2.cmd("e cfg.sandbox.grain=' + grain + ';e cfg.sandbox=true");'
        result, sent = request(setup=setup)
        assert result == failure and sent is None, (grain, result)

    for reply in [b"", b"not json", b"null", b"[]", b"{}", b'"string"', b"42", b"1.5",
                  b'{"status":200,"body":"bad!","encoding":"base64"}',
                  b'{"status":200,"body":"A===","encoding":"base64"}',
                  b'{"status":200,"body":"","encoding":"plain"}',
                  b'{"status":99,"body":"","encoding":"base64"}',
                  b'{"status":600,"body":"","encoding":"base64"}',
                  b'{"status":"200","body":"","encoding":"base64"}', None]:
        assert request(reply=reply)[0] == failure, reply
    assert request(reply_size=24 * 1024 * 1024)[0] == failure
    assert request(reply=envelope(b"x" * (16 * 1024 * 1024 + 1)), summary=True)[0] == failure
    assert request(reply=envelope(b"x" * (16 * 1024 * 1024)), summary=True)[0] == {
        "status": 200, "size": 16 * 1024 * 1024}
    for data_js in ['"x".repeat(2 * 1024 * 1024 + 1)', "'\"'.repeat(1024 * 1024)"]:
        result, sent = request("POST", data_js=data_js)
        assert result == failure and sent is None
    for completion in [struct.pack("<i", -5), b"\x00\x00", None]:
        start = time.monotonic()
        assert request(completion=completion)[0] == failure
        if completion is None:
            assert time.monotonic() - start >= 0.9, "pending reads were treated as EOF"
    print("Guest HTTP: relay envelopes, GET/POST, URL mapping, bounds, sandbox, timeout and cleanup passed")


if __name__ == "__main__":
    main()
