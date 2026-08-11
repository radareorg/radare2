#!/usr/bin/env python3
# minimal static server for the jslinux www/ dir (correct wasm mime type)
import http.server
import socketserver
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".wasm": "application/wasm",
        ".webmanifest": "application/manifest+json",
        ".cfg": "text/plain",
    }

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print("serving on http://localhost:%d" % port)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
