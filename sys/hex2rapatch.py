#!/usr/bin/env python

""" Portable python script to convert Intel hex file to rapatch """

from intelhex import IntelHex
import argparse

parser = argparse.ArgumentParser(
    prog='ihex2rapatch',
    description='Convert Intel hex file to radare2 patch file')

parser.add_argument('source', help='Intel Hex source file')
parser.add_argument('target', help='radare2 patch target file')

args = parser.parse_args()

f = open(args.target, 'w')

ih = IntelHex(args.source)
for segment in ih.segments():
    f.write(hex(segment[0]) + ': ')
    for x in range(segment[0],segment[1]):
        f.write(f'{ih[x]:02x}')
    f.write('\n')

f.close()
