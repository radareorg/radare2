#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mangle shellcode strings in src/*.c into out/*.c using a randomly
chosen combination (subset + order) of: xor, rol, ror, transposition.
Also emits a matching out/decrypt.inc.c containing a static inline
function:

    static inline ut8 *sc_decrypt(const ut8 *buf, size_t len)

that returns a heap-allocated decrypted copy (same size as input).

Usage:
  python3 scmangle.py src/x86-linux-binsh.c [src/other.c ...]
  optional flags:
    --out-dir out           # default: out
    --seed 0x12345678       # fix randomness for reproducibility

Notes:
- Only string literals are transformed; everything else is preserved.
- All strings found are concatenated for encryption, then split back
  to the original literal boundaries after mangling.
- The same randomly chosen algorithm and parameters are used for all
  input files in a single run, and written to decrypt.inc.c.
"""

import argparse
import os
import re
import sys
from typing import List, Tuple
import glob

# -------------------- Helpers: bit ops & PRNG used by both sides --------------------

def rol8(v: int, r: int) -> int:
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF

def ror8(v: int, r: int) -> int:
    r &= 7
    return ((v >> r) | (v << (8 - r))) & 0xFF

class LCG:
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF
    def next(self) -> int:
        # Numerical Recipes LCG
        self.state = (1664525 * self.state + 1013904223) & 0xFFFFFFFF
        return self.state

def gen_perm(n: int, seed: int) -> List[int]:
    perm = list(range(n))
    if n <= 1:
        return perm
    prng = LCG(seed)
    for i in range(n - 1, 0, -1):
        j = prng.next() % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm

# -------------------- C string literal parsing/rewriting --------------------

STR_RE = re.compile(r'"([^"\\]|\\.)*"', re.DOTALL)

OCT_RE = re.compile(r'^[0-7]{1,3}')
HEX_RE = re.compile(r'^[0-9A-Fa-f]{1,2}')

def _decode_c_string_inner(s: str) -> bytes:
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch != '\\':
            out.append(ord(ch))
            i += 1
            continue
        # escape sequence
        i += 1
        if i >= n:
            out.append(ord('\\'))
            break
        esc = s[i]
        i += 1
        if esc == 'x':
            m = HEX_RE.match(s[i:])
            if not m or len(m.group(0)) == 0:
                out.append(ord('x'))
            else:
                val = int(m.group(0), 16)
                out.append(val & 0xFF)
                i += len(m.group(0))
        elif '0' <= esc <= '7':
            m = OCT_RE.match(esc + s[i:])
            val = int(m.group(0), 8)
            out.append(val & 0xFF)
            i += len(m.group(0)) - 1
        elif esc == 'n':
            out.append(0x0A)
        elif esc == 'r':
            out.append(0x0D)
        elif esc == 't':
            out.append(0x09)
        elif esc == '\\':
            out.append(0x5C)
        elif esc == '"':
            out.append(0x22)
        elif esc == '\'':
            out.append(0x27)
        elif esc == '0':
            out.append(0x00)
        else:
            # Unknown escape: keep as raw char
            out.append(ord(esc))
    return bytes(out)

def find_string_segments(text: str) -> List[Tuple[int, int, bytes]]:
    segs = []
    for m in STR_RE.finditer(text):
        full = m.group(0)
        inner = full[1:-1]
        b = _decode_c_string_inner(inner)
        segs.append((m.start(), m.end(), b))
    return segs

def bytes_to_c_literal(b: bytes) -> str:
    return '"' + ''.join('\\x%02x' % x for x in b) + '"'

# -------------------- Encryption pipeline selection & application --------------------

def choose_ops(rng: LCG):
    # Choose random subset size in [2,4] and shuffle order
    ops_all = ['xor', 'rol', 'ror', 'transpose']
    # Simple subset selection using RNG
    # Pick count k
    k = (rng.next() % 3) + 2  # 2..4
    # Shuffle ops_all deterministically with rng
    shuffled = ops_all[:]
    for i in range(len(shuffled) - 1, 0, -1):
        j = rng.next() % (i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    subset = shuffled[:k]
    ops = []
    for op in subset:
        if op == 'xor':
            key = (rng.next() & 0xFF) or 0xA7  # avoid 0
            ops.append({'op': 'xor', 'key': key})
        elif op == 'rol':
            bits = ((rng.next() % 7) + 1)  # 1..7
            ops.append({'op': 'rol', 'bits': int(bits)})
        elif op == 'ror':
            bits = ((rng.next() % 7) + 1)  # 1..7
            ops.append({'op': 'ror', 'bits': int(bits)})
        elif op == 'transpose':
            seed = rng.next() or 0xC0FFEE01
            ops.append({'op': 'transpose', 'seed': int(seed & 0xFFFFFFFF)})
    return ops

def apply_ops_encrypt(data: bytes, ops: List[dict]) -> bytes:
    b = bytearray(data)
    for op in ops:
        if op['op'] == 'xor':
            k = op['key']
            for i in range(len(b)):
                b[i] ^= k
        elif op['op'] == 'rol':
            r = op['bits']
            for i in range(len(b)):
                b[i] = rol8(b[i], r)
        elif op['op'] == 'ror':
            r = op['bits']
            for i in range(len(b)):
                b[i] = ror8(b[i], r)
        elif op['op'] == 'transpose':
            seed = op['seed']
            perm = gen_perm(len(b), seed)
            out = bytearray(len(b))
            # encryption: out[perm[i]] = b[i]
            for i, v in enumerate(b):
                out[perm[i]] = v
            b = out
        else:
            raise ValueError(f"Unknown op: {op}")
    return bytes(b)

# -------------------- C decryptor emitter --------------------

def render_decrypt_inc_c(ops: List[dict]) -> str:
    # Decrypt must apply inverse ops in reverse order
    c = []
    c.append("/* Auto-generated by scmangle.py */")
    c.append("#include <stdint.h>")
    c.append("#include <stdlib.h>")
    c.append("#include <string.h>")
    c.append("")
    c.append("static inline uint8_t rol8_u8(uint8_t v, unsigned int r) { r &= 7; return (uint8_t)(((v << r) | (v >> (8 - r))) & 0xFF); }")
    c.append("static inline uint8_t ror8_u8(uint8_t v, unsigned int r) { r &= 7; return (uint8_t)(((v >> r) | (v << (8 - r))) & 0xFF); }")
    c.append("static inline uint32_t lcg_next_u32(uint32_t *s) { *s = 1664525u * (*s) + 1013904223u; return *s; }")
    c.append("static inline void gen_perm_idx(size_t n, uint32_t seed, size_t *perm) {")
    c.append("    for (size_t i = 0; i < n; i++) perm[i] = i;")
    c.append("    if (n <= 1) return;")
    c.append("    for (size_t i = n - 1; i > 0; i--) {")
    c.append("        uint32_t r = lcg_next_u32(&seed) % (uint32_t)(i + 1);")
    c.append("        size_t j = (size_t)r;")
    c.append("        size_t t = perm[i]; perm[i] = perm[j]; perm[j] = t;")
    c.append("    }")
    c.append("}")
    c.append("")
    c.append("static inline ut8 *sc_decrypt(const ut8 *buf, size_t len) {")
    c.append("    if (!buf) return NULL;")
    c.append("    ut8 *cur = (ut8*)malloc(len);")
    c.append("    if (!cur) return NULL;")
    c.append("    if (len) memcpy(cur, buf, len);")

    # Apply inverse operations in reverse order
    for op in reversed(ops):
        if op['op'] == 'xor':
            c.append(f"    /* inverse: xor key=0x{op['key']:02x} */")
            c.append("    for (size_t i = 0; i < len; i++) cur[i] ^= (ut8)" + str(op['key']) + ";")
        elif op['op'] == 'rol':
            r = op['bits']
            c.append(f"    /* inverse: ror {r} */")
            c.append(f"    for (size_t i = 0; i < len; i++) cur[i] = (ut8)ror8_u8(cur[i], {r});")
        elif op['op'] == 'ror':
            r = op['bits']
            c.append(f"    /* inverse: rol {r} */")
            c.append(f"    for (size_t i = 0; i < len; i++) cur[i] = (ut8)rol8_u8(cur[i], {r});")
        elif op['op'] == 'transpose':
            seed = op['seed']
            c.append(f"    /* inverse: untranspose seed=0x{seed:08x} */")
            c.append("    if (len > 1) {")
            c.append("        size_t *perm = (size_t*)malloc(sizeof(size_t) * len);")
            c.append("        if (!perm) { free(cur); return NULL; }")
            c.append(f"        gen_perm_idx(len, 0x{seed:08x}u, perm);")
            c.append("        ut8 *tmp = (ut8*)malloc(len);")
            c.append("        if (!tmp) { free(perm); free(cur); return NULL; }")
            c.append("        for (size_t i = 0; i < len; i++) tmp[i] = cur[perm[i]];")
            c.append("        free(cur); cur = tmp; free(perm);")
            c.append("    }")
        else:
            raise ValueError(f"Unknown op: {op}")

    c.append("    return cur;")
    c.append("}")
    c.append("")
    # Also emit a tiny helper for callers that want in-place-like API
    c.append("static inline ut8 *sc_decrypt_dup(const ut8 *buf, size_t len) { return sc_decrypt(buf, len); }")
    return "\n".join(c) + "\n"

# -------------------- Driver --------------------

def process_file(path: str, out_dir: str, ops: List[dict]):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    segs = find_string_segments(text)
    if not segs:
        print(f"[skip] No string literals found in {path}")
        return
    all_bytes = b''.join(b for (_, _, b) in segs)
    enc = apply_ops_encrypt(all_bytes, ops)
    # Re-split into original segment sizes
    parts = []
    pos = 0
    last = 0
    out_text_parts = []
    for (start, end, bseg) in segs:
        out_text_parts.append(text[last:start])
        seg_len = len(bseg)
        chunk = enc[pos:pos+seg_len]
        pos += seg_len
        out_text_parts.append(bytes_to_c_literal(chunk))
        last = end
    out_text_parts.append(text[last:])
    mangled = ''.join(out_text_parts)

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, os.path.basename(path))
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(mangled)
    print(f"[ok] Wrote {out_path} ({len(all_bytes)} bytes mangled across {len(segs)} literals)")


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('inputs', nargs='+', help='src/*.c files to mangle')
    ap.add_argument('--out-dir', default='out')
    ap.add_argument('--seed', type=lambda x: int(x, 0), default=None,
                    help='seed for reproducibility (e.g., 1234 or 0xdeadbeef)')
    args = ap.parse_args(argv)

    # Seed selection
    if args.seed is None:
        import time
        seed = (os.getpid() * 0x9E3779B1) ^ int(time.time_ns() & 0xFFFFFFFF)
        seed &= 0xFFFFFFFF
    else:
        seed = args.seed & 0xFFFFFFFF

    rng = LCG(seed)
    ops = choose_ops(rng)

    # Summarize the chosen ops
    def op_desc(op):
        if op['op'] == 'xor':
            return f"xor(key=0x{op['key']:02x})"
        if op['op'] == 'rol':
            return f"rol({op['bits']})"
        if op['op'] == 'ror':
            return f"ror({op['bits']})"
        if op['op'] == 'transpose':
            return f"transpose(seed=0x{op['seed']:08x})"
        return str(op)

    print("[plan] ops (encryption order): " + " -> ".join(op_desc(op) for op in ops))

    # Emit decryptor header once per run
    decrypt_c = render_decrypt_inc_c(ops)
    os.makedirs(args.out_dir, exist_ok=True)
    dec_path = os.path.join(args.out_dir, 'decrypt.inc.c')
    with open(dec_path, 'w', encoding='utf-8') as f:
        f.write(decrypt_c)
    print(f"[ok] Wrote {dec_path}")

    # Expand glob patterns in inputs (meson passes globs as literal strings)
    expanded_inputs = []
    for p in args.inputs:
        matches = glob.glob(p)
        if matches:
            expanded_inputs.extend(matches)
        else:
            expanded_inputs.append(p)

    # Process each input
    for p in expanded_inputs:
        process_file(p, args.out_dir, ops)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
