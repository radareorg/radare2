#!/usr/bin/env python

""" Portable python script to read version from configure.acr """

import sys

with open(sys.argv[1], 'r') as f:
    for l in f:
        if 'SDBVER=' in l:
            version = l.strip('\n').split('=')[1]
            sys.stdout.write(version + '\n')
