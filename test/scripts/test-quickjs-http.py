#!/usr/bin/env python3

import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        status = 201 if self.command == "POST" else 200
        body = json.dumps({
            "method": self.command,
            "authorization": self.headers.get("Authorization"),
            "content_types": self.headers.get_all("Content-Type", []),
            "data": data.decode(),
        }).encode()
        if self.path == "/missing":
            status, body = 404, b"missing"
        elif self.path == "/empty":
            status, body = 204, b""
        elif self.path == "/text":
            body = "hello món\x00end".encode()
        elif self.path == "/disconnect":
            self.close_connection = True
            return
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *_):
        pass


def main():
    root = Path(__file__).resolve().parents[2]
    executable = os.environ.get("R2", str(root / "binr/radare2/radare2"))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    cases = [
        ("GET", "/", "Authorization: Bearer test", None),
        ("POST", "/", "Authorization: Bearer test\ncontent-type: application/json", '{"prompt":"hello món"}'),
        ("POST", "/", "", None),
        ("GET", "/missing", "", None),
        ("GET", "/empty", "", None),
        ("GET", "/text", "", None),
        ("GET", "/disconnect", "", None),
    ]
    script = ""
    for method, path, headers, data in cases:
        args = [method, url + path, headers]
        if data is not None:
            args.append(data)
        call = "r2.http(" + ",".join(json.dumps(arg) for arg in args) + ")"
        script += "try { console.log(JSON.stringify(" + call + ")); }"
        script += " catch (e) { console.log(JSON.stringify({error:e.message})); }"
    try:
        transports = ["0", "1"] if shutil.which("curl") else ["0"]
        for curl in transports:
            env = dict(os.environ, R2_CURL=curl)
            result = subprocess.run([executable, "-NNq", "-e", "scr.color=0",
                                     "-e", "log.level=0", "-c", "'js " + script,
                                     "-c", "q", "-"], env=env, capture_output=True,
                                    text=True, timeout=30, check=True)
            assert not result.stderr, result.stderr
            responses = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(responses) == len(cases), result.stdout
            for response, case in zip(responses[:3], cases[:3]):
                method, _, _, data = case
                assert response.get("status") == (201 if method == "POST" else 200), (curl, response)
                received = json.loads(response["body"])
                assert received["method"] == method
                assert received["data"] == (data or "")
            assert json.loads(responses[0]["body"])["authorization"] == "Bearer test"
            post = json.loads(responses[1]["body"])
            assert post["authorization"] == "Bearer test"
            assert post["content_types"] == ["application/json"], post
            assert json.loads(responses[2]["body"])["content_types"] == ["application/x-www-form-urlencoded"]
            assert responses[3] == {"status": 404, "body": "missing"}
            assert responses[4] == {"status": 204, "body": ""}
            assert responses[5] == {"status": 200, "body": "hello món\x00end"}
            assert responses[6] == {"error": "HTTP request failed or denied"}
        print("QuickJS HTTP: GET/POST, headers, status, UTF-8/NUL bodies and transport failures passed")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
