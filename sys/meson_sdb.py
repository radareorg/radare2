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
DATADIRS = [os.path.abspath(p) for p in DATADIRS]
BLACKLIST = ['Makefile', 'makefile']
EXTENSIONS = ['txt', '']

MESON = 'python meson.py' if os.path.isfile('meson.py') else 'meson'
NINJA = 'ninja'

def convert_sdb(folder, f):
    """ Convert f to sdb format """
    base, _ = get_base_extension(f)
    inf = os.path.join(folder, f)
    sdb = os.path.join(folder, base) + '.sdb'
    print('Converting {} to {}'.format(inf, sdb))
    os.system('{sdb} {outf} = <{inf}'.format(sdb=SDB, outf=sdb, inf=inf))

def get_base_extension(f):
    """ file.sdb.txt => file, .txt """
    n = f.split('.')
    if len(n) == 1: return n[0], ''
    return n[0], n[-1]

def handle_folder(folder):
    """ Convert each suitable file inside specified folder to sdb file """
    print('Handling {} directory...'.format(folder))
    for f in os.listdir(folder):
        if f in BLACKLIST:
            continue
        base, ext = get_base_extension(f)
        absf = os.path.join(folder, f)
        if os.path.isdir(absf) and not os.path.islink(absf):
            handle_folder(absf)
            continue
        if ext not in EXTENSIONS:
            continue
        convert_sdb(folder, f)

def main():
    # Create sdb binary
    r = os.system('{meson} {sdbdir} {builddir}'.format(meson=MESON, sdbdir=SDBDIR, builddir=BUILDDIR))
    if r: exit(r)
    r = os.system('{ninja} -C {builddir}'.format(ninja=NINJA, builddir=BUILDDIR))
    if r: exit(r)

    # Create .sdb files
    print('Generating sdb files.')
    print('Looking up {}'.format(', '.join(DATADIRS)))
    for folder in DATADIRS:
        handle_folder(folder)
    print('Done')

if __name__ == '__main__':
    main()
