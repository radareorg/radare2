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
BLACKLIST = ['Makefile']

MESON = 'python meson.py' if os.path.isfile('meson.py') else 'meson'
NINJA = 'ninja'

def convert_sdb(inf, outf):
    """ Convert inf to outf.sdb """
    print('Converting {} to {}'.format(inf, outf))
    os.system('{sdb} {outf} = <{inf}'.format(sdb=SDB, outf=outf, inf=inf))

def get_extension(inf):
    """ Handles files with multiple extensions e.g. .sdb.txt """
    n = inf.split('.')
    return inf, n[0], n[-1]

def main():
    # Create sdb binary
    if os.path.exists(BUILDDIR):
        print('{} folder exists. Exiting.'.format(BUILDDIR))
        return
    r = os.system('{meson} {sdbdir} {builddir}'.format(meson=MESON, sdbdir=SDBDIR, builddir=BUILDDIR))
    r = os.system('{ninja} -C {builddir}'.format(ninja=NINJA, builddir=BUILDDIR))
    if r: exit(r)

    # Create .sdb files
    i = 0
    l = len(DATADIRS)
    while i < l:
        folder = DATADIRS[i]
        print(folder)
        for f in os.listdir(folder):
            if f in BLACKLIST:
                continue
            inf, base, ext = get_extension(f)
            inf = os.path.join(folder, inf)
            if os.path.isdir(inf) and not os.path.islink(inf):
                DATADIRS.append(inf)
                l += 1
                continue
            outf = '.'.join([os.path.join(folder, base), 'sdb'])
            convert_sdb(inf, outf)
        i += 1
    print('Done.')

if __name__ == '__main__':
    main()
