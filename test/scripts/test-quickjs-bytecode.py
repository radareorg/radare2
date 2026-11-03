#!/usr/bin/env python3

import os
from pathlib import Path
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
R2 = os.environ.get("R2", str(ROOT / "binr/radare2/radare2"))
MAGIC = b"R2JSBC\r\n"
DELIMITER = "\n✄\n".encode()


def run(*commands, script=None):
    args = [R2, "-NNq", "-e", "scr.color=0"]
    if script:
        args += ["-i", str(script)]
    for command in commands:
        args += ["-c", command]
    result = subprocess.run(args + ["-"], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result
    return result.stdout, result.stderr


def package(files):
    files = [(name, source.encode()) for name, source in files]
    return ("📦\n".encode()
            + b"\n".join(f"{len(source)} {name}".encode() for name, source in files)
            + DELIMITER + DELIMITER.join(source for _, source in files))


def roundtrip(path, source, expected, commands=()):
    path.write_bytes(source)
    binary = path.with_name(path.name[:-6] + ".bin.r2.js")
    assert run("js: " + str(path), *commands) == (expected, "")
    for command, flag in [("jsc", 0), ("jscz", 1)]:
        assert run(command + " " + str(path)) == ("", ""), "compilation executed the script"
        compiled = binary.read_bytes()
        assert compiled.startswith(MAGIC)
        assert struct.unpack_from("<I", compiled, 12)[0] & 1 == flag
        assert struct.unpack_from("<I", compiled, 20)[0] == len(compiled) - 40
        # Each execution starts in a separate VM, with no source file available.
        hidden = path.with_suffix(".hidden")
        path.rename(hidden)
        try:
            for prefix in ["js: ", ". ", "#!qjs "]:
                assert run(prefix + str(binary), *commands) == (expected, ""), (command, prefix)
            assert run(*commands, script=binary) == (expected, "")
        finally:
            hidden.rename(path)
    return binary


def main():
    with tempfile.TemporaryDirectory(prefix="r2-bytecode-") as directory:
        directory = Path(directory)
        roundtrip(directory / 'plain "quoted".r2.js', b'''
var value = 42;
function answer() { return value; }
console.log("plain", answer(), r2.cmd("?v 42").trim());
console.log(answer.toString().includes("return value"));
Promise.resolve().then(() => console.log("async"));
''', "plain 42 0x2a\ntrue\nasync\n")
        roundtrip(directory / "plugin.r2.js", b'''
r2.plugin("core", function () {
  return { name: "bytecode-test", call: function (input) {
    if (input === "t1") { console.log("plugin callback"); return true; }
    return false;
  }};
});
''', "plugin callback\n", ("t1",))
        roundtrip(directory / "module.r2.js", b'''-import { r2 } from "r2papi";
console.log("module", r2.cmd("?v 42").trim());
''', "module 0x2a\n")
        bundled = package([
            ("/bundle/main.js", '''import { answer } from "./lib.js";
import { r2 } from "r2papi";
console.log("bundle", answer(), r2.cmd("?v 42").trim());'''),
            ("/bundle/lib.js", '''import { value } from "./value.js";
export function answer() { return value; }'''),
            ("/bundle/value.js", "export const value = 42;"),
            ("/bundle/asset.txt", "non-JavaScript asset"),
        ])
        binary = roundtrip(directory / "bundle.r2.js", bundled, "bundle 42 0x2a\n")
        roundtrip(directory / "cyclic.r2.js", package([
            ("/cycle/main.js", '''import { get } from "./lib.js";
export const value = 42; console.log("cycle", get());'''),
            ("/cycle/lib.js", '''import { value } from "./main.js";
export function get() { return value; }'''),
        ]), "cycle 42\n")
        # Exercise more than one LZ4 block, including a partial last block.
        large = ("function large() {\n" + "".join(
            f'console.log("line {i}: répétition", {i});\n' for i in range(600)
        ) + "}\nconsole.log(typeof large);\n").encode()
        roundtrip(directory / "large.r2.js", large, "function\n")
        roundtrip(directory / "empty.r2.js", b"", "")

        good = binary.read_bytes()
        invalid = directory / "invalid.bin.r2.js"
        corruptions = [good[:length] for length in [0, 4, 8, 39, 40, len(good) - 1]]
        corruptions += [good + b"extra", b"console.log('source fallback');"]
        for offset in [0, 8, 12, 16, 20, 24, 32, 40]:
            damaged = bytearray(good)
            damaged[offset] ^= 0xff
            corruptions.append(bytes(damaged))
        for data in corruptions:
            invalid.write_bytes(data)
            stdout, stderr = run("js: " + str(invalid), "js console.log('alive')")
            assert stdout == "alive\n", stdout
            assert "Cannot read JavaScript bytecode" in stderr, stderr

        bad = directory / "syntax.r2.js"
        bad.write_text("function broken(")
        for command in ["jsc", "jscz"]:
            stdout, stderr = run(command + " " + str(bad))
            assert not stdout and "SyntaxError" in stderr, stderr
            assert not bad.with_name("syntax.bin.r2.js").exists()
        for data in ["📦\n".encode(),
                     "📦\n999999 /bad.js\n✄\nshort".encode(),
                     b"console.log('truncated');\0console.log('hidden');"]:
            bad.write_bytes(data)
            assert "Cannot compile JavaScript file" in run("jsc " + str(bad))[1]
        assert "Expected a source .r2.js file" in run("jsc " + str(binary))[1]
        assert "Cannot read" in run("jsc " + str(directory / "missing.r2.js"))[1]
        sandboxed = directory / "sandbox.r2.js"
        sandboxed.write_text("console.log('must not run')")
        stdout, stderr = run("e cfg.sandbox.grain=all,!script", "e cfg.sandbox=true",
                             "jsc " + str(sandboxed))
        assert not stdout and "Scripting is disabled in sandbox mode" in stderr, stderr
        assert not sandboxed.with_name("sandbox.bin.r2.js").exists()
    print("QuickJS bytecode: source/bytecode/LZ4 parity, imports, cycles, plugins, entry points,")
    print("multiple blocks, empty files, corruption, syntax errors and sandbox checks passed")


if __name__ == "__main__":
    main()
