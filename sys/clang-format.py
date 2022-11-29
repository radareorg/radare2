#!/usr/bin/env python3

import glob
import os
import sys

dirlist = [
    "binrz",
    "libr",
    "shlr/ar",
    "shlr/bochs",
    "shlr/gdb",
    "shlr/java",
    "shlr/ptrace-wrap",
    "shlr/qnx",
    "shlr/rar",
    "shlr/tcc",
    "shlr/winkd",
    "test/unit",
]

skiplist = [
    "/gnu/",
    "libr/anal/arch/vax/",
    "libr/asm/arch/riscv/",
    "libr/asm/arch/sh/gnu/",
    "libr/asm/arch/i8080/",
    "libr/asm/arch/z80/",
    "libr/asm/arch/avr/",
    "libr/arch/p/arm/aarch64/",
    "libr/hash/xxhash/",
    "libr/bin/mangling/cxx/",
    "libr/util/bdiff.c",
]

pattern = ["*.c", "*.cpp", "*.h", "*.hpp", "*.inc"]


def skip(filename):
    for s in skiplist:
        if s in filename:
            return True
    return False


try:
    for d in dirlist:
        print("Processing directory: {0}".format(d))
        for pat in pattern:
            print("Processing pattern: {0}".format(pat))
            for filename in glob.iglob(d + "/**/" + pat, recursive=True):
                if not skip(filename):
                    CMD = "clang-format -style=file -i {0}".format(filename)
                    print(CMD)
                    os.system(CMD)

except KeyboardInterrupt:
    print("clang-format.py interrupted by the user.")
    sys.exit(1)
