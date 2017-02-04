#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
MAX_METACASE_EXAMPLES = 2
MARKER_NUMBER = "_NUM_"
MARKER_REGISTER = "_REG_"
CONCURRENCY = 8
ASM_ENGINE = "x86"  # See rasm2 -L. Note this script is not x86-specific
REFERENCE_ASM_ENGINE = "x86.ks"

mygil = Lock()
cases = {}
meta_cases = {}

def cannonical(s):
    return re.sub("0x[0-9a-fA-F]+|\d+", MARKER_NUMBER, s)


def meta_cannonical(s):
    s = cannonical(s)
    for r in re.findall("\[(.+?)]", s):
        r2 = re.sub("[a-z]+", MARKER_REGISTER, r)
        s = s.replace(r, r2)
    return s


def gen_testcase(cause, ins, inpairs, oins=""):
    inskey = cannonical(ins)
    insmkey = meta_cannonical(ins)
    with mygil:
        meta_cases[insmkey] = meta_cases.get(insmkey, 0) + 1
        if (meta_cases[insmkey] >= MAX_METACASE_EXAMPLES):
            # print("BLOCKED %s" % insmkey)
            return
        elif(inskey not in cases):
            cases[inskey] = dict(
                cause=cause, ins=ins, inpairs=inpairs,
                oins=oins, case=inskey, metacase=insmkey)
            return cases[inskey]


def check_hexpairs(orig_input_hexpairs):
    output = rasm2("-D", "-a", ASM_ENGINE, orig_input_hexpairs)
    output = output.stdout.split(b"\n")[0].decode()
    output = re.split("\s+", output, 2)[-1]
    input_hexpairs, input_ins = re.split("\s+", output, 1)

    if input_ins == 'invalid':
        coutput = rasm2("-D", "-a", REFERENCE_ASM_ENGINE, orig_input_hexpairs)
        coutput = coutput.stdout.split(b"\n")[0].decode()
        coutput = re.split("\s+", coutput, 2)[-1]
        cinput_hexpairs, cinput_ins = re.split("\s+", coutput, 1)
        if (cinput_ins != 'invalid'):
            print(cinput_hexpairs,cinput_ins)
            return gen_testcase("false invalid", cinput_ins,
                            cinput_hexpairs, input_ins)
        return

    try:
        output_hexpairs = rasm2(
            "-a", ASM_ENGINE, input_ins).stdout.split(b"\n")[0]
    except sh.ErrorReturnCode_1 as e:
        if "Cannot assemble" in str(e):
            return gen_testcase("roundtrip fail", input_ins, input_hexpairs)
        return

    output_ins = rasm2("-d", "-a", ASM_ENGINE, output_hexpairs)
    output_ins = output_ins.stdout.split(b"\n")[0].decode()

    if (input_ins != output_ins):
        return gen_testcase("roundtrip mismatch", input_ins,
                            input_hexpairs, output_ins)

def main():

    if (len(sys.argv) != 2):
        print("Usage: %s <path to binary file>" % sys.argv[0])
        return 0

    if not os.path.exists(sys.argv[1]):
        print("No such file %s" % sys.argv[1])
        return 1

    fsize = os.stat(sys.argv[1]).st_size

    if (fsize < MAX_OPLEN):
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
            if (res):
                print("%s\n" % json.dumps(res, indent=4))

if __name__ == '__main__':
    import sys
    sys.exit(main())
