# Compiling JavaScript scripts

`jsc script.r2.js` compiles a JavaScript script or a multi-module JavaScript
bundle to QuickJS bytecode in `script.bin.r2.js`. Compilation does not run the
script. `jscz script.r2.js` writes the same output filename using libr/util's
built-in LZ4 compressor. An existing output file is replaced after successful
compilation.

Run either format with the usual script commands:

```text
js: script.bin.r2.js
. script.bin.r2.js
```

The command-line `r2 -i script.bin.r2.js binary` and `#!qjs script.bin.r2.js`
work too. Scripts share the usual JavaScript VM, helpers and plugin APIs.
Bundles keep their JavaScript modules and relative imports. Plain scripts keep
global scope; the leading `-` convention for module scripts is also supported.
Function source and debug information are preserved, so compilation can make
files larger. Compression is optional and is particularly useful for bundles.

The JavaScript binding `r2.compile("script.r2.js", true)` performs the same
operation as `jscz`; omit the second argument for uncompressed output. The
compiler uses a separate VM, so it does not change the running script's globals
or execute module initializers.

Only load compiled files from a trusted producer. QuickJS bytecode is not a
portable or hardened interchange format. Recompile when changing the radare2
build, QuickJS version or pointer size. Header and checksum validation detect
incompatible or damaged files; they do not authenticate the producer.

## File format, version 1

The 40-byte header contains these little-endian fields:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Magic: `R2JSBC\r\n` |
| 8 | 4 | Container version: 1 |
| 12 | 4 | Flags: bit 0 = LZ4, bit 1 = terminal raw mode |
| 16 | 4 | Uncompressed payload length |
| 20 | 4 | Stored payload length |
| 24 | 8 | Hash of QuickJS version, radare2 Git revision and pointer size |
| 32 | 8 | `r_str_hash64_seed(payload, length, 0)` checksum |

The uncompressed payload is a sequence of records. Each record starts with a
32-bit name length and a 32-bit bytecode length, followed by the name bytes
(without a terminator) and the result of `JS_WriteObject` with
`JS_WRITE_OBJ_BYTECODE`. The first record is the entry point. Other records
hold bundle modules, which are loaded on demand, including circular imports.
Non-JavaScript bundle assets are ignored, as in the source loader.

An LZ4 payload uses the blocks emitted by `r_lz4_compress`: each block has a
32-bit compressed length followed by its compressed data. Blocks expand to at
most 8192 bytes. The loader checks block bounds, the exact decompressed length
and the checksum before passing any bytecode to QuickJS. The uncompressed
payload is limited to 64 MiB.
