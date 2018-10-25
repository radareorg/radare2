#!/usr/bin/env python

""" Portable python script to read version from configure.acr """

import sys

with open('configure.acr', 'r') as f:
    f.readline()
    sys.stdout.write(f.readline().split()[1])
