## Meson build for radare2

import argparse
import inspect
import logging
import os
import re
import subprocess
import sys

ROOT = None
BUILDDIR = 'build'
SDB_BUILDDIR = 'build_sdb'
SDB = os.path.join(SDB_BUILDDIR, 'sdb')
BLACKLIST = ['Makefile', 'makefile']
EXTENSIONS = ['sdb.txt']
MESON = None
PYTHON = None
BACKENDS = ['ninja', 'vs2015', 'vs2017']
log = None

def setGlobalVariables():
    """ Set global variables """
    global log
    global ROOT
    global MESON
    global PYTHON

    if os.name == 'posix':
        cmd = 'which meson'
    else:
        cmd = 'where meson.py'
    MESON = os.popen(cmd).read().split('\n')[0]
    #if os.name == 'nt' and ' ' in MESON:
    #    MESON = '"{}"'.format(MESON)

    PYTHON = sys.executable
    #if os.name == 'nt' and ' ' in PYTHON:
    #    PYTHON = '"{}"'.format(PYTHON)

    ROOT = os.path.abspath(inspect.getfile(inspect.currentframe()) +
            os.path.join(os.path.pardir, os.path.pardir, os.path.pardir))
    #if os.name == 'nt' and ' ' in ROOT:
    #    ROOT = '"{}"'.format(ROOT)

    logging.basicConfig(format='[Meson][%(levelname)s]: %(message)s',
            level=logging.DEBUG)
    log = logging.getLogger('r2-meson')
    log.debug('Root:{} Meson:{} Python:{}'.format(ROOT, MESON, PYTHON))

def meson(root, build, prefix=None, backend=None, release=False, shared=False):
    """ Start meson build (i.e. python meson.py ./ build) """
    command = [PYTHON, MESON, root, build]
    if prefix:
        command += ['--prefix={}'.format(prefix)]
    if backend:
        command += ['--backend={}'.format(backend)]
    if release:
        command += ['--buildtype=release']
    if shared:
        command += ['--default-library', 'shared']
    else:
        command += ['--default-library', 'static']

    log.debug('Invoking meson: {}'.format(command))
    ret = subprocess.call(command)
    if ret != 0:
        log.error('Meson error. Exiting.')
        sys.exit(1)

def ninja(folder):
    """ Start ninja build (i.e. ninja -C build) """
    command = ['ninja', '-C', os.path.join(ROOT, folder)]
    log.debug('Invoking ninja: {}'.format(command))
    ret = subprocess.call(command)
    if ret != 0:
        log.error('Ninja error. Exiting.')
        sys.exit(1)

def convert_sdb(folder, f):
    """ Convert f to sdb format """
    base, _ = get_base_extension(f)
    inf = os.path.join(folder, f)
    sdb = os.path.join(folder, base) + '.sdb'
    log.debug('Converting {} to {}'.format(inf, sdb))
    os.system('{sdb} {outf} = <{inf}'.format(sdb=SDB, outf=sdb, inf=inf))

def get_base_extension(f):
    """ file.sdb.txt => file, .txt """
    n = f.split('.')
    if len(n) == 1: return n[0], ''
    return n[0], '.'.join(n[1:])

def handle_folder(folder):
    """ Convert each suitable file inside specified folder to sdb file """
    log.debug('Handling {} directory...'.format(folder))
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

def xp_compat(builddir):
    with open(os.path.join(builddir, 'REGEN.vcxproj'), 'r') as f:
        version = re.search('<PlatformToolset>(.*)</PlatformToolset>', f.read()).group(1)

    log.debug('Translating from %s to %s_xp' % (version, version))
    newversion=version+'_xp'

    for root, dirs, files in os.walk(builddir):
        for f in files:
            if f.endswith('.vcxproj'):
                with open(os.path.join(root, f), 'r') as proj:
                    c = proj.read()
                c = c.replace(version, newversion)
                with open(os.path.join(root, f), 'w') as proj:
                    proj.write(c)
                    log.debug("%s .. OK" % f)

def build_sdb(args):
    """ Build and generate sdb files """
    log.info('Building SDB')
    cmd = 'ECHO %CD%' if os.name == 'nt' else 'pwd'
    cd = os.popen(cmd).read().rstrip()
    meson(os.path.join(ROOT, 'shlr', 'sdb'), SDB_BUILDDIR, prefix=cd)
    ninja(SDB_BUILDDIR)

    # Create .sdb files
    log.info('Generating sdb files.')
    with open('Makefile', 'r') as f:
        line = ''
        while 'DATADIRS' not in line:
            line = f.readline()
    datadirs = line.split('=')[1].split()
    datadirs = [os.path.abspath(p) for p in datadirs]
    log.debug('Looking up {}'.format(', '.join(datadirs)))
    for folder in datadirs:
        handle_folder(folder)
    log.debug('Done')

def build_r2(args):
    """ Build radare2 """
    log.info('Building radare2')
    if args.backend != 'ninja':
        if not os.path.exists(args.dir):
            meson(ROOT, args.dir, args.prefix, args.backend, args.release,
                    args.shared)
        if args.xp:
            log.info('Running XP compat script')
            xp_compat(BUILDDIR)
        if not args.project:
            log.info('Starting msbuild')
            project = os.path.join(ROOT, args.dir, 'radare2.sln')
            subprocess.call(['msbuild', project])
    else:
        if not os.path.exists(args.dir):
            meson(ROOT, args.dir, args.prefix, args.backend, args.release,
                    args.shared)
        ninja(args.dir)


def build(args):
    """ Prepare requirements and build radare2 """
    # Prepare capstone
    capstone_path = os.path.join(ROOT, 'shlr', 'capstone')
    if not os.path.isdir(capstone_path):
        log.info('Cloning capstone')
        subprocess.call('git clone -b next --depth 10 https://github.com/aquynh/capstone.git'.split() + [capstone_path])

    # Build radare2
    build_r2(args)

    # Build sdb
    build_sdb(args)

def install(args):
    """ Install radare2 """
    log.warning('Install not implemented yet.')
    return
    # TODO
    #if os.name == 'posix':
    #    os.system('DESTDIR="{destdir}" ninja -C {build} install'
    #            .format(destdir=destdir, build=args.dir))

def main():
    # Create logger and get applications paths
    setGlobalVariables()

    # Create parser
    parser = argparse.ArgumentParser(description='Mesonbuild scripts for radare2')
    parser.add_argument('--project', action='store_true',
            help='Create a visual studio project and do not build.')
    parser.add_argument('--release', action='store_true',
            help='Set the build as Release (remove debug info)')
    parser.add_argument('--backend', action='store', choices=BACKENDS,
            default='ninja', help='Choose build backend')
    parser.add_argument('--shared', action='store_true',
            help='Link dynamically (shared library) rather than statically')
    parser.add_argument('--prefix', action='store', default=None,
            help='Set project installation prefix (default: /usr/local)')
    parser.add_argument('--install', action='store_true',
            help='Install radare2 after building')
    parser.add_argument('--dir', action='store', default=BUILDDIR,
            help='Destination build directory (default: {})'.format(BUILDDIR),
            required=False)
    parser.add_argument('--xp', action='store_true',
            help='Adds support for Windows XP')
    args = parser.parse_args()

    # Check arguments
    if args.project and args.backend == 'ninja':
        log.error('--project is not compatible with --backend ninja')
        sys.exit(1)
    if args.xp and args.backend == 'ninja':
        log.error('--xp is not compatible with --backend ninja')
        sys.exit(1)

    # Build it!
    log.debug('Arguments: {}'.format(args))
    build(args)
    if args.install:
        install(args)

if __name__ == '__main__':
    main()
