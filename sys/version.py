#!/usr/bin/env python

""" Portable python script to read version from configure.acr """

import sys

full_version = False
no_newline = False

for arg in sys.argv[1:]:
    if arg == '-h' or arg == '--help':
        print('Only flag accepted here is --full-version')
        sys.exit(0)
    elif arg == '-n':
        no_newline = True
    elif arg == '--full-version':
        full_version = True
    else:
        print('Option %s not supported' % (arg,))
        sys.exit(1)
import os
r2root=os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
with open(os.path.join(r2root, 'configure.acr'), 'r') as f:
    f.readline()
    version = f.readline().split()[1]
    if no_newline:
        sys.stdout.write(version)
    else:
        sys.stdout.write(version + '\n')
    if full_version:
        versions = version.split('.')
        version_major = versions[0] if len(versions) > 0 else 0
        version_minor = versions[1] if len(versions) > 1 else 0
        version_patch = versions[2].replace('-git', '') if len(versions) > 2 else 0
        version_number = "%d%02d%02d"%(int(version_major), int(version_minor), int(version_patch))
        sys.stdout.write(version_major + '\n')
        sys.stdout.write(version_minor + '\n')
        sys.stdout.write(version_patch + '\n')
        sys.stdout.write(version_number + '\n')
