#!/usr/bin/env python3

import base64
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


class Upstream(http.server.BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.calls.append((self.command, self.path, dict(self.headers), data))
        status = 200
        body = b"hello\x00\xff"
        if self.path == "/v1/post":
            status, body = 201, data
        elif self.path == "/v1/missing":
            status, body = 404, b'{"error":"missing"}'
        elif self.path == "/v1/redirect":
            status, body = 302, b"redirect"
        elif self.path == "/v1/large":
            body = b"x" * (16 * 1024 * 1024 + 1)
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/unexpected-redirect")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_POST = do_GET

    def log_message(self, *_):
        pass


def main():
    root = Path(__file__).resolve().parents[2]
    php = os.environ.get("PHP", "php")
    subprocess.run([php, "-l", str(root / "dist/jslinux/web/http.php")], check=True)
    subprocess.run([php, "-r", "exit(extension_loaded('curl') ? 0 : 1);"], check=True)
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, R2_HTTP_TOKEN="relay-test-token",
               R2_HTTP_UPSTREAM=f"http://127.0.0.1:{upstream.server_port}/v1")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([php, "-S", f"127.0.0.1:{port}", "-t",
                                    str(root / "dist/jslinux/web")],
                                   env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise AssertionError("PHP server exited")
                    time.sleep(0.05)
            else:
                raise AssertionError("PHP server did not start")

            def request(value=None, outer_method="POST", raw=None):
                payload = dict(token="relay-test-token", **(value or {}))
                body = json.dumps(payload).encode() if raw is None else raw
                req = urllib.request.Request(f"http://127.0.0.1:{port}/http.php",
                                             data=body if outer_method == "POST" else None,
                                             headers={"Content-Type": "application/octet-stream"},
                                             method=outer_method)
                try:
                    response = opener.open(req, timeout=10)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    assert response.headers["Cache-Control"] == "no-store"
                    return response.status, json.load(response)

            status, result = request()
            assert status == 200 and result["status"] == 200
            assert result["encoding"] == "base64"
            assert base64.b64decode(result["body"]) == b"hello\x00\xff"
            text = '{"prompt":"hello món"}'
            status, result = request({"method": "POST", "path": "/post",
                                      "headers": "Content-Type: application/json\nAuthorization: Bearer test",
                                      "data": text})
            assert status == 200 and result["status"] == 201
            assert base64.b64decode(result["body"]) == text.encode()
            method, path, headers, data = Upstream.calls[-1]
            assert (method, path, data) == ("POST", "/v1/post", text.encode())
            headers = {name.lower(): value for name, value in headers.items()}
            assert headers["authorization"] == "Bearer test"
            assert headers["content-type"] == "application/json"
            assert "cookie" not in headers and "relay-test-token" not in str(headers)
            assert request({"method": "POST", "path": "/post"})[1]["body"] == ""
            assert request({"path": "/missing"})[1]["status"] == 404
            before = len(Upstream.calls)
            assert request({"path": "/redirect"})[1]["status"] == 302
            assert len(Upstream.calls) == before + 1
            assert request({"path": "/large"})[0] == 502

            before = len(Upstream.calls)
            assert request(outer_method="GET")[0] == 405
            assert request(raw=b'{"token":"wrong"}')[0] == 403
            assert request(raw=b'{}')[0] == 403
            for raw in [b"invalid", b"[]", b"null"]:
                assert request(raw=raw)[0] == 400
            assert request(raw=b"x" * (2 * 1024 * 1024 + 1))[0] == 413
            for value in [{"method": "DELETE"}, {"data": "GET body"}, {"path": 1},
                          {"headers": []}, {"data": {}}, {"path": "//example.com/"},
                          {"path": "https://example.com/"}, {"path": "/\\example.com"},
                          {"path": "/\r\nHost: example.com"}, {"path": "/#fragment"},
                          {"headers": "Host: example.com"}, {"headers": "Cookie: secret"},
                          {"headers": "Authorization: test\r\nHost: example.com"},
                          {"headers": "Authorization: a\nauthorization: b"}]:
                assert request(value)[0] == 400, value
            assert len(Upstream.calls) == before
            print("JSLinux PHP relay: GET/POST, headers, binary data, errors, limits and access checks passed")
        except Exception:
            log.seek(0)
            print(log.read().decode())
            raise
        finally:
            process.terminate()
            process.wait(timeout=5)
            upstream.shutdown()
            upstream.server_close()
            thread.join()


if __name__ == "__main__":
    main()
