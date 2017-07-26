# This scripts aims to compile sdb and generate .sdb files for the meson build
# Assumes you are in radare2 root directory

import os

BUILDDIR = 'build_sdb'
SDBDIR = os.path.join('shlr', 'sdb')
SDB = os.path.join(BUILDDIR, 'sdb')
with open('Makefile', 'r') as f:
    line = ''
    while 'DATADIRS' not in line:
        line = f.readline()
DATADIRS = line.split('=')[1].split()

MESON = 'python meson.py' if os.path.isfile('meson.py') else 'meson'
NINJA = 'ninja'

# Create sdb binary
r = os.system('{meson} {sdbdir} {builddir}'.format(meson=MESON, sdbdir=SDBDIR, builddir=BUILDDIR))
r = os.system('{ninja} -C {builddir}'.format(ninja=NINJA, builddir=BUILDDIR))
if r: exit(r)

# Create .sdb files
for folder in DATADIRS:
    for f in os.listdir(folder):
        inf, ext = os.path.splitext(f)
        if ext and 'txt' not in ext:
            continue
        while '.' in inf:
            inf, ext = os.path.splitext(f)
        inf = os.path.join(folder, inf)
        outf = '.'.join([inf, 'sdb'])
        print('Converting {} to {}'.format(inf, outf))
        os.system('{sdb} {outf} = <{inf}'.format(sdb=SDB, outf=outf, inf=inf))

