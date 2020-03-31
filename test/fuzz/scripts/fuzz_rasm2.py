#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
# rasm2 fuzzer
# ============
#
# Takes a binary executable as argument and uses its contents to feed
# the specified disassembler/assembler engines. Together with a reference
# engine(s), the input and outputs are chained through and any
# incompatabilities are turned into test cases which are written to stdout
# as streaming json.
#
# This program processes the disassembled instructions and groups them into
# similar "families", filtering out examples which are similar to those
# already reported, improving signal-to-noise ratio.
#
#
# History:
# v1 - Initial version
# v2 - Seperated asm/disasm engine constants
# v3 - fixed synchronization and added 3 level of canonical
#
# SchumBlubBlub - 2017
# Public Domain.

import os
import sh
import re
import json
from multiprocessing import Lock
from concurrent.futures import ProcessPoolExecutor
from binascii import hexlify

from sh import rasm2, dd

MAX_OPLEN = 20
MAX_METACASE_EXAMPLES = 1
MAX_META_META_CASE_EXAMPLES = 1
MARKER_NUMBER = "_NUM_"
MARKER_REGISTER = "_REG_"
MARKER_META_REGISTER = "_MREG_"
MARKER_WIDTH_MARKER = "_WIDTH_"
MARKER_SEGREG_MARKER = "_SEGREG_"
CONCURRENCY = 8
ASM_ENGINE = "x86.nz"  # See rasm2 -L. Note this script is not x86-specific
DISASM_ENGINE = "x86"  # capstone
REFERENCE_ASM_ENGINE = "x86.ks"
REFERENCE_DISASM_ENGINE = None  # no alternative right now

re_regs = re.compile(
    "al|ah|ax|eah|eax|rah|rax|bl|bh|bx|ebx|rbh|rbx|cl|ch|cx|ecx|rcx|dl|dh"
    "|dx|edl|edh|edx|rdx|si|esi|rsi|di|edi|rdi|sp|esp|rsp|bp|ebp|rbp|ip|eip"
    "|rip|r8|r9|r10|r11|r12|r13|r14|r15|r8d|r9d|r10d|r11d|r12d|r13d|r14d|"
    "r15d|r8w|r9w|r10w|r11w|r12w|r13w|r14w|r15w")
re_seg = re.compile("(cs|ds|es|fs|gs):")


def cannonical(s):
    return re.sub("0x[0-9a-fA-F]+|\d+", MARKER_NUMBER, s)


def meta_cannonical(s):
    s = cannonical(s)
    for r in re.findall("\[(.+?)]", s):
        r2 = re.sub("[a-z]+", MARKER_REGISTER, r)
        s = s.replace(r, r2)
    return s


def meta_meta_cannonical(s):
    s = meta_cannonical(s)
    s = re.sub('byte|word|dword|qword', MARKER_WIDTH_MARKER, s)
    for r in re_regs.findall(s):
        s = re.sub(r, MARKER_REGISTER, s)
    for r in re_seg.findall(s):
        s = re.sub(r, MARKER_SEGREG_MARKER, s)
    return s


def gen_testcase(cause, ins, inpairs, oins=""):
    inskey = cannonical(ins)
    insmkey = meta_cannonical(ins)
    insmmkey = meta_meta_cannonical(ins)
    return dict(
        cause=cause,
        ins=ins,
        inpairs=inpairs,
        oins=oins,
        case=inskey,
        metacase=insmkey,
        metametacase=insmmkey)


def check_hexpairs(orig_input_hexpairs):
    output = rasm2("-D", "-a", DISASM_ENGINE, orig_input_hexpairs)
    output = output.stdout.split(b"\n")[0].decode()
    output = re.split("\s+", output, 2)[-1]
    input_hexpairs, input_ins = re.split("\s+", output, 1)

    if input_ins == 'invalid':
        if REFERENCE_DISASM_ENGINE:
            coutput = rasm2(
                "-D", "-a", REFERENCE_DISASM_ENGINE, orig_input_hexpairs)
            coutput = coutput.stdout.split(b"\n")[0].decode()
            coutput = re.split("\s+", coutput, 2)[-1]
            cinput_hexpairs, cinput_ins = re.split("\s+", coutput, 1)
            if (cinput_ins != 'invalid'):
                print(cinput_hexpairs, cinput_ins)
                return gen_testcase("Disassemble False Fail", cinput_ins,
                                    cinput_hexpairs, input_ins)
        return

    try:
        output_hexpairs = rasm2(
            "-a", ASM_ENGINE, input_ins).stdout.split(b"\n")[0]
    except sh.ErrorReturnCode_1 as e:
        if "Cannot assemble" in str(e):
            return gen_testcase("Assemble False Fail", input_ins, input_hexpairs)
        return

    output_ins = rasm2("-d", "-a", DISASM_ENGINE, output_hexpairs)
    output_ins = output_ins.stdout.split(b"\n")[0].decode()

    if (input_ins != output_ins):
        return gen_testcase("Assemble != Dis+Assemble", input_ins,
                            input_hexpairs, output_ins)


def main():
    cases = {}
    meta_cases = {}
    meta_meta_cases = {}

    if len(sys.argv) != 2:
        print("Usage: %s <path to binary file>" % sys.argv[0])
        return 0

    if not os.path.exists(sys.argv[1]):
        print("No such file %s" % sys.argv[1])
        return 1

    fsize = os.stat(sys.argv[1]).st_size

    if fsize < MAX_OPLEN:
        print("muy pequeño:  %s" % sys.argv[1])
        return 1

    with open(sys.argv[1], "rb") as f:
        input_data = f.read()

    pool = ProcessPoolExecutor(CONCURRENCY)
    for offset in range(0, fsize-20, CONCURRENCY):
        inputs = [hexlify(input_data[o:o+MAX_OPLEN])
                  for o in range(offset, offset+CONCURRENCY)]
        tasks = pool.map(check_hexpairs, inputs)
        for res in tasks:
            if not res:
                continue
            inskey = res['case']
            insmkey = res['metacase']
            insmmkey = res['metametacase']
            meta_meta_cases[insmmkey] = meta_meta_cases.get(insmmkey, 0) + 1
            meta_cases[insmkey] = meta_cases.get(insmkey, 0) + 1
            if (meta_cases[insmkey] > MAX_METACASE_EXAMPLES or
                    meta_meta_cases[insmmkey] > MAX_META_META_CASE_EXAMPLES):
                pass
            elif inskey not in cases:
                cases[inskey] = cases.get(inskey, 0) + 1
                print("%s\n" % json.dumps(res, indent=4))

if __name__ == '__main__':
    import sys
    sys.exit(main())
