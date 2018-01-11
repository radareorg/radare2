## Meson build for radare2

import argparse
import glob
import inspect
import logging
import os
import re
import shutil
import subprocess
import sys

from mesonbuild import mesonmain

BUILDDIR = 'build'
SDB_BUILDDIR = 'build_sdb'
SDB = os.path.join(SDB_BUILDDIR, 'sdb')

BACKENDS = ['ninja', 'vs2015', 'vs2017']
BLACKLIST = ['Makefile', 'makefile']
EXTENSIONS = ['sdb.txt']

PATH_FMT = {}

ROOT = None
log = None

def setGlobalVariables():
    """ Set global variables """
    global log
    global ROOT

    ROOT = os.path.abspath(inspect.getfile(inspect.currentframe()) +
            os.path.join(os.path.pardir, os.path.pardir, os.path.pardir))
    #if os.name == 'nt' and ' ' in ROOT:
    #    ROOT = '"{}"'.format(ROOT)

    logging.basicConfig(format='[Meson][%(levelname)s]: %(message)s',
            level=logging.DEBUG)
    log = logging.getLogger('r2-meson')
    log.debug('Root:{}'.format(ROOT))

def meson(root, build, prefix=None, backend=None, release=False, shared=False):
    """ Start meson build (i.e. python meson.py ./ build) """
    command = [root, build]
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
    launcher = os.path.join(ROOT, 'sys', 'meson.py')
    meson_run(command, launcher)

def meson_run(args, launcher):
    ret = mesonmain.run(args, launcher)
    if ret != 0:
        log.error('Meson error. Exiting.')
        sys.exit(1)

def ninja(folder, install=False):
    """ Start ninja build (i.e. ninja -C build) """
    command = ['ninja', '-C', os.path.join(ROOT, folder)]
    if install: command.append('install')
    log.debug('Invoking ninja: {}'.format(command))
    ret = subprocess.call(command)
    if ret != 0:
        log.error('Ninja error. Exiting.')
        sys.exit(1)

def msbuild(project):
    log.info('Starting msbuild %s' % project)
    ret = subprocess.call(['msbuild', project])
    if ret != 0:
        log.error('MSbuild error. Exiting.')
        sys.exit(1)

def copytree(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT)
    log.debug('copytree "%s" -> "%s"' % (src, dst))
    shutil.copytree(src, dst)

def move(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT)
    term = os.path.sep if os.path.isdir(dst) else ''
    log.debug('move "%s" -> "%s%s"' % (src, dst, term))
    for file in glob.iglob(src):
        shutil.move(file, dst)

def copy(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT)
    term = os.path.sep if os.path.isdir(dst) else ''
    log.debug('copy "%s" -> "%s%s"' % (src, dst, term))
    for file in glob.iglob(src):
        shutil.copy2(file, dst)

def makedirs(path):
    path = path.format(**PATH_FMT)
    log.debug('makedirs "%s"' % path)
    os.makedirs(path)

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
    log.info('Running XP compat script')

    with open(os.path.join(builddir, 'REGEN.vcxproj'), 'r') as f:
        version = re.search('<PlatformToolset>(.*)</PlatformToolset>', f.read()).group(1)

    if version.endswith('_xp'):
        log.debug('Skipping %s\\*.vcxproj' % builddir)
        return

    log.debug('Translating from %s to %s_xp' % (version, version))
    newversion = version+'_xp'

    for root, dirs, files in os.walk(builddir):
        for f in files:
            if f.endswith('.vcxproj'):
                with open(os.path.join(root, f), 'r') as proj:
                    c = proj.read()
                c = c.replace(version, newversion)
                with open(os.path.join(root, f), 'w') as proj:
                    proj.write(c)
                    log.debug("%s .. OK" % f)

def win_install(args):
    global PATH_FMT

    with open(os.path.join(ROOT, 'configure.acr')) as f:
        f.readline()
        version = f.readline().split(' ')[1].rstrip()

    PATH_FMT['ROOT'] = ROOT
    PATH_FMT['DIST'] = args.install
    PATH_FMT['BIN'] = os.path.join(args.prefix, 'bin')
    PATH_FMT['LIB'] = os.path.join(args.prefix, 'lib')
    PATH_FMT['BUILDDIR'] = os.path.join(ROOT, args.dir)
    PATH_FMT['R2_VERSION'] = version

    if args.backend == 'ninja':
        ninja(args.dir, install=True)
    else:
        for d in (r'{BIN}', r'{LIB}'):
            d = d.format(**PATH_FMT)
            if os.path.exists(d):
                shutil.rmtree(d)
            os.makedirs(d)
        copy(r'{BUILDDIR}\binr\**\*.exe', r'{BIN}')
        copy(r'{BUILDDIR}\libr\**\*.dll', r'{BIN}')
        copy(r'{BUILDDIR}\libr\**\*.lib', r'{LIB}')
        copy(r'{BUILDDIR}\libr\**\*.a', r'{LIB}')
    makedirs(r'{DIST}')
    move(r'{BIN}\*.exe', r'{DIST}')
    move(r'{BIN}\*.dll', r'{DIST}')
    if args.copylib:
        move(r'{LIB}\*.lib', r'{DIST}')
        move(r'{LIB}\*.a', r'{DIST}')
    copytree(r'{ROOT}\shlr\www', r'{DIST}\www')
    copytree(r'{ROOT}\libr\magic\d\default', r'{DIST}\share\radare2\{R2_VERSION}\magic')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\syscall')
    copy(r'{ROOT}\libr\syscall\d\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\syscall')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\fcnsign')
    copy(r'{ROOT}\libr\anal\d\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\fcnsign')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\opcodes')
    copy(r'{ROOT}\libr\anal\d\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\opcodes')
    makedirs(r'{DIST}\include\libr\sdb')
    makedirs(r'{DIST}\include\libr\r_util')
    copy(r'{ROOT}\libr\include\*.h', r'{DIST}\include\libr')
    copy(r'{ROOT}\libr\include\sdb\*.h', r'{DIST}\include\libr\sdb')
    copy(r'{ROOT}\libr\include\r_util\*.h', r'{DIST}\include\libr\r_util')
    makedirs(r'{DIST}\share\doc\radare2')
    copy(r'{ROOT}\doc\fortunes.*', r'{DIST}\share\doc\radare2')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\format\dll')
    copy(r'{ROOT}\libr\bin\d\elf32', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\elf64', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\elf_enums', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\pe32', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\trx', r'{DIST}\share\radare2\{R2_VERSION}\format')
    copy(r'{ROOT}\libr\bin\d\dll\*.sdb', r'{DIST}\share\radare2\{R2_VERSION}\format\dll')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\cons')
    copy(r'{ROOT}\libr\cons\d\*', r'{DIST}\share\radare2\{R2_VERSION}\cons')
    makedirs(r'{DIST}\share\radare2\{R2_VERSION}\hud')
    copy(r'{ROOT}\doc\hud', r'{DIST}\share\radare2\{R2_VERSION}\hud\main')

def build_sdb(args):
    """ Build and generate sdb files """
    log.info('Building SDB')
    if not os.path.exists(SDB_BUILDDIR):
        meson(os.path.join(ROOT, 'shlr', 'sdb'), SDB_BUILDDIR,
              args.prefix, args.backend, args.release, args.shared)
    if args.backend != 'ninja':
        if args.xp:
            xp_compat(os.path.join(ROOT, SDB_BUILDDIR))
        if not args.project:
            project = os.path.join(ROOT, SDB_BUILDDIR, 'sdb.sln')
            msbuild(project)
    else:
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
    if not os.path.exists(args.dir):
        meson(ROOT, args.dir, args.prefix, args.backend,
              args.release, args.shared)
    if args.backend != 'ninja':
        if args.xp:
            xp_compat(os.path.join(ROOT, args.dir))
        if not args.project:
            project = os.path.join(ROOT, args.dir, 'radare2.sln')
            msbuild(project)
    else:
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
    if os.name == 'nt':
        win_install(args)
        return
    log.warning('Install not implemented yet.')
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
    parser.add_argument('--dir', action='store', default=BUILDDIR,
            help='Destination build directory (default: {})'.format(BUILDDIR),
            required=False)
    parser.add_argument('--xp', action='store_true',
            help='Adds support for Windows XP')
    if os.name == 'nt':
        parser.add_argument('--install', help='Installation directory')
        parser.add_argument('--copylib', action='store_true',
            help='Copy static libraries to the installation directory')
    else:
        parser.add_argument('--install', action='store_true',
            help='Install radare2 after building')
    args = parser.parse_args()

    # Check arguments
    if args.project and args.backend == 'ninja':
        log.error('--project is not compatible with --backend ninja')
        sys.exit(1)
    if args.xp and args.backend == 'ninja':
        log.error('--xp is not compatible with --backend ninja')
        sys.exit(1)
    if os.name == 'nt' and args.install and os.path.exists(args.install):
        log.error('%s already exists' % args.install)
        sys.exit(1)

    # Build it!
    log.debug('Arguments: {}'.format(args))
    build(args)
    if args.install:
        install(args)

if __name__ == '__main__':
    # meson internals
    if len(sys.argv) > 1 and sys.argv[1] in ('test', '--internal'):
        launcher = os.path.realpath(sys.argv[0])
        meson_run(sys.argv[1:], launcher)
        sys.exit()
    main()
