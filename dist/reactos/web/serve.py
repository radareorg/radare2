#!/usr/bin/env python3
"""Static file server with HTTP Range support, for testing the v86 page.

python3's builtin http.server does not implement Range requests, which the
on-demand disk streaming needs; this wrapper adds them.
"""
import os
import re
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class RangeHandler(SimpleHTTPRequestHandler):
    extensions_map = dict(SimpleHTTPRequestHandler.extensions_map)
    extensions_map[".wasm"] = "application/wasm"
    extensions_map[".img"] = "application/octet-stream"

    def end_headers(self):
        self.send_header("Accept-Ranges", "bytes")
        if self.path.split("?")[0].endswith(("/", "index.html", "config.js", "sw.js")):
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def do_GET(self):
        rng = self.headers.get("Range")
        if not rng:
            return super().do_GET()
        path = self.translate_path(self.path)
        try:
            size = os.path.getsize(path)
        except OSError:
            return self.send_error(404)
        m = re.match(r"bytes=(\d*)-(\d*)$", rng.strip())
        if not m:
            return self.send_error(416)
        a, b = m.groups()
        if a:
            start = int(a)
            end = int(b) if b else size - 1
        else:
            if not b:
                return self.send_error(416)
            start = max(0, size - int(b))
            end = size - 1
        if start >= size:
            return self.send_error(416)
        end = min(end, size - 1)
        length = end - start + 1
        self.send_response(206)
        self.send_header("Content-Type", self.guess_type(path))
        self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.send_header("Content-Length", str(length))
        self.end_headers()
        with open(path, "rb") as f:
            f.seek(start)
            left = length
            while left > 0:
                chunk = f.read(min(1 << 16, left))
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except BrokenPipeError:
                    return
                left -= len(chunk)

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print("serving on http://localhost:%d" % port)
    ThreadingHTTPServer(("", port), RangeHandler).serve_forever()
