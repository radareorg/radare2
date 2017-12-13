## Meson build for radare2

import argparse
import inspect
import logging
import os
import subprocess
import sys

ROOT = None
BUILDDIR = 'build'
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

def build_sdb(args):
    """ Build and generate sdb files """
    log.info('Building SDB')
    log.debug('TODO Merge scripts')
    return os.system('{python} {path}'.format(python=PYTHON,
        path=os.path.join(ROOT, 'sys', 'meson_sdb.py')))

def build_r2(args):
    """ Build radare2 """
    log.info('Building radare2')
    if args.backend != 'ninja':
        if not os.path.exists(args.dir):
            meson(ROOT, args.dir, args.prefix, args.backend, args.release,
                    args.shared)
        if args.xp:
            log.info('Running XP compat script')
            log.debug('TODO Merge this script')
            meson_extra = os.path.join(ROOT, 'sys', 'meson_extra.py')
            os.system('python {meson_extra}'.format(meson_extra=meson_extra))
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
