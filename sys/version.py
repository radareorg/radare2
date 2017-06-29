#!/usr/bin/env python

""" Portable python script to read version from configure.acr """

with open('configure.acr', 'r') as f:
    f.readline()
    print(f.readline().split()[1])
