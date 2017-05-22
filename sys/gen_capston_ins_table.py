#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
gen_capston_ins_table.py

Parse capstone header file and dump JSON map for inst_id->name lookup.

"""

import sys
import re
import json
from cffi import FFI


def parse_definition(s):
    r = re.finditer("^typedef\s+enum\s+(\w+_insn) \{", s, flags=re.MULTILINE)
    m = next(r)
    if not m:
        raise RuntimeError("Failed to parse")
    tpname = m.group(1)
    ss = "typedef enum " + s.split(tpname, 1)[-1].split("//>")[0]
    enum_prefix = ss.split("\n")[1].strip().rsplit("_", 1)[0]
    if not enum_prefix or len(enum_prefix) > 10:
        raise RuntimeError("Failed to parse")
    return tpname, enum_prefix, ss


def create_dict(filename, suffix="//>"):
    with open(filename, "r") as f:
        s = f.read()

    ffi = FFI()
    tpname, enum_prefix, enum = parse_definition(s)
    ffi.cdef(enum)

    x = ffi.new("%s*" % tpname)
    c = ffi.dlopen('c')
    d = {getattr(c, n): n for n in dir(c) if n.startswith(enum_prefix)}

    return d


def main():

    if (len(sys.argv) != 2):
        print("Usage: %s <path to capstone (x86.h|arm.h|...)>" % sys.argv[0])
        return
    d = create_dict(sys.argv[1])

    print(json.dumps(d, indent=4))

if __name__ == '__main__':
    sys.exit(main())
