#!/usr/bin/env python3

import os
from pathlib import Path
import socketserver
import struct
import subprocess
import threading


DIR_LIMIT = 16 * 1024 * 1024
TVERSION, TATTACH, TWALK, TOPEN, TREAD, TCLUNK = 100, 104, 110, 112, 116, 120
ROOT_QID = struct.pack("<BIQ", 0x80, 0, 1)


def p9_string(value):
    return struct.pack("<H", len(value)) + value


body = (struct.pack("<HI", 0, 0) + struct.pack("<BIQ", 0, 0, 2)
        + struct.pack("<IIIQ", 0o644, 0, 0, 14)
        + p9_string(b"hello.txt") + p9_string(b"tester") + p9_string(b"") * 2)
RECORD = struct.pack("<H", len(body)) + body


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        opened = 0
        offset = 0
        while header := self.rfile.read(7):
            size, request, tag = struct.unpack("<IBH", header)
            body = self.rfile.read(size - 7)
            reply_type = request + 1
            if request == TVERSION:
                reply = body
            elif request == TATTACH:
                reply = ROOT_QID
            elif request == TWALK:
                reply = struct.pack("<H", 0)
            elif request == TOPEN:
                opened += 1
                offset = 0
                reply = ROOT_QID + struct.pack("<I", 0)
            elif request == TCLUNK:
                self.server.clunks += 1
                reply = b""
            elif request == TREAD:
                _, requested_offset, count = struct.unpack("<IQI", body)
                assert requested_offset == offset, (requested_offset, offset)
                entries = self.server.entries if opened == 1 else 1
                remaining = count if entries is None else entries * len(RECORD) - offset
                data = RECORD * (min(count, remaining) // len(RECORD))
                if opened == 1:
                    self.server.reads += 1
                # Keep the unfixed client from allocating indefinitely during this test.
                if offset > DIR_LIMIT + count:
                    reply_type, reply = 107, p9_string(b"test safety limit")
                else:
                    reply = struct.pack("<I", len(data)) + data
                    offset += len(data)
            else:
                raise AssertionError(f"unexpected 9P request {request}")
            self.wfile.write(struct.pack("<IBH", 7 + len(reply), reply_type, tag) + reply)


def check_listing(executable, label, entries, limited=False):
    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        server.entries, server.reads, server.clunks = entries, 0, 0
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            commands = (f"m /mnt 9fs tcp:127.0.0.1:{server.server_address[1]};"
                        "mdq /mnt~?;mdq /mnt~?;?e done")
            result = subprocess.run([executable, "-Nq", "-e", "scr.color=0", "-c", commands, "--"],
                                    capture_output=True, text=True, timeout=15, check=True)
        finally:
            server.shutdown()
            thread.join()
        expected_count = 0 if limited else entries
        assert result.stdout == f"{expected_count}\n1\ndone\n", (label, result.stdout)
        diagnostic = f"Directory listing exceeds {DIR_LIMIT} bytes"
        assert (diagnostic in result.stderr) == limited, (label, result.stderr)
        assert server.clunks >= 2, (label, "directory fids were not clunked")
        chunk_entries = (8192 - 11) // len(RECORD)
        expected_reads = (DIR_LIMIT // len(RECORD) // chunk_entries + 1 if limited
                          else (entries + chunk_entries - 1) // chunk_entries + 1)
        assert server.reads == expected_reads, (label, server.reads, expected_reads)
        print(f"PASS: {label} ({server.reads} reads)")


def main():
    root = Path(__file__).resolve().parents[2]
    executable = os.environ.get("R2", str(root / "binr/radare2/radare2"))
    for label, entries, limited in [
        ("empty directory", 0, False),
        ("one entry", 1, False),
        ("multiple replies", 300, False),
        ("exactly at budget", DIR_LIMIT // len(RECORD), False),
        ("one entry over budget", DIR_LIMIT // len(RECORD) + 1, True),
        ("endless directory", None, True),
    ]:
        check_listing(executable, label, entries, limited)


if __name__ == "__main__":
    main()
