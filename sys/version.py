#!/usr/bin/env python

""" Portable python script to read version from configure.acr """

import sys

with open('configure.acr', 'r') as f:
    f.readline()
    version = f.readline().split()[1]
    sys.stdout.write(version + '\n')
    versions = version.split('.')
    version_major = versions[0] if len(versions) > 0 else 0
    version_minor = versions[1] if len(versions) > 1 else 0
    version_patch = versions[2].replace('-git', '') if len(versions) > 2 else 0
    sys.stdout.write(version_major + '\n')
    sys.stdout.write(version_minor + '\n')
    sys.stdout.write(version_patch + '\n')
