#!/usr/bin/env python
"""Meson build for radare2"""

import argparse
import glob
import logging
import os
import re
import shutil
import subprocess
import sys

BUILDDIR = 'build'
BACKENDS = ['ninja', 'vs2015', 'vs2017', 'vs2019']

PATH_FMT = {}
R2_PATH = {
    'R2_LIBDIR': r'lib',
    'R2_INCDIR': r'include',
    'R2_DATDIR': r'share',
    'R2_WWWROOT': r'{R2_DATDIR}\www',
    'R2_SDB': r'{R2_DATDIR}',
    'R2_ZIGNS': r'{R2_DATDIR}\zigns',
    'R2_THEMES': r'{R2_DATDIR}\cons',
    'R2_FORTUNES': r'{R2_DATDIR}\doc',
    'R2_FLAGS': r'{R2_DATDIR}\flag',
    'R2_HUD': r'{R2_DATDIR}\hud'
}

MESON = None
ROOT = None
log = None

def set_global_variables():
    """[R_API] Set global variables"""
    global log
    global ROOT
    global MESON

    ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))

    logging.basicConfig(format='[%(name)s][%(levelname)s]: %(message)s',
                        level=logging.DEBUG)
    log = logging.getLogger('r2-meson')

    with open(os.path.join(ROOT, 'configure.acr')) as f:
        f.readline()
        version = f.readline().split()[1].rstrip()

    if os.name == 'nt':
        meson = os.path.join(os.path.dirname(sys.executable), 'Scripts', 'meson.exe')
        if os.path.exists(meson):
            MESON = [meson]
        else:
            meson = os.path.join(os.path.dirname(sys.executable), 'Scripts', 'meson.py')
            MESON = [sys.executable, meson]
    else:
        MESON = ['meson']

    PATH_FMT['ROOT'] = ROOT
    PATH_FMT['R2_VERSION'] = version

    log.debug('Root: %s', ROOT)
    log.debug('Meson: %s', MESON)
    log.debug('Version: %s', version)

def meson(command, rootdir=None, builddir=None, prefix=None, backend=None,
          release=False, shared=None, *, options=[]):
    """[R_API] Invoke meson"""
    cmd = MESON + [command]
    if rootdir:
        cmd.append(rootdir)
    if builddir:
        cmd.append(builddir)
    if prefix:
        cmd.append('--prefix={}'.format(prefix))
    if backend:
        cmd.append('--backend={}'.format(backend))
    if release:
        cmd.append('--buildtype=release')
    if shared != None:
        cmd.append('--default-library={}'.format('shared' if shared else 'static'))
    if options:
        cmd.extend(options)

    log.debug('Invoking meson: %s', cmd)
    ret = subprocess.call(cmd)
    if ret != 0:
        log.error('Meson error. Exiting.')
        sys.exit(1)

def ninja(folder, *targets):
    """[R_API] Invoke ninja"""
    command = ['ninja', '-C', folder]
    if targets:
        command.extend(targets)
    log.debug('Invoking ninja: %s', command)
    ret = subprocess.call(command)
    if ret != 0:
        log.error('Ninja error. Exiting.')
        sys.exit(1)

def msbuild(project, *params):
    """[R_API] Invoke MSbuild"""
    command = ['msbuild', project]
    if params:
        command.extend(params)
    log.info('Invoking MSbuild: %s', command)
    ret = subprocess.call(command)
    if ret != 0:
        log.error('MSbuild error. Exiting.')
        sys.exit(1)

def copytree(src, dst, exclude=()):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT).format(**PATH_FMT)
    log.debug('copytree "%s" -> "%s"', src, dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*exclude) if exclude else None)

def move(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT).format(**PATH_FMT)
    term = os.path.sep if os.path.isdir(dst) else ''
    log.debug('move "%s" -> "%s%s"', src, dst, term)
    for file in glob.iglob(src):
        shutil.move(file, dst)

def copy(src, dst):
    src = src.format(**PATH_FMT)
    dst = dst.format(**PATH_FMT).format(**PATH_FMT)
    term = os.path.sep if os.path.isdir(dst) else ''
    log.debug('copy "%s" -> "%s%s"', src, dst, term)
    for file in glob.iglob(src, recursive='**' in src):
        shutil.copy2(file, dst)

def makedirs(path):
    path = path.format(**PATH_FMT).format(**PATH_FMT)
    log.debug('makedirs "%s"', path)
    os.makedirs(path)

def xp_compat(builddir):
    log.info('Running XP compat script')

    with open(os.path.join(builddir, 'REGEN.vcxproj'), 'r') as f:
        version = re.search('<PlatformToolset>(.*)</PlatformToolset>', f.read()).group(1)

    if version.endswith('_xp'):
        log.info('Skipping %s', builddir)
        return

    log.debug('Translating from %s to %s_xp', version, version)
    newversion = version+'_xp'

    for f in glob.iglob(os.path.join(builddir, '**', '*.vcxproj'), recursive=True):
        with open(f, 'r') as proj:
            c = proj.read()
        c = c.replace(version, newversion)
        with open(f, 'w') as proj:
            proj.write(c)
            log.debug("%s .. OK", f)

def build(args):
    """ Build radare2 """
    log.info('Building radare2')
    r2_builddir = os.path.join(ROOT, args.dir)
    options = ['-D%s' % x for x in args.options]
    if args.webui:
        options.append('-Duse_webui=true')
    if args.local:
        options.append('-Dlocal=true')
    if not os.path.exists(r2_builddir):
        meson('setup', builddir=r2_builddir, prefix=args.prefix, backend=args.backend,
              release=args.release, shared=args.shared, options=options)
    if args.backend != 'ninja':
        # XP support was dropped in Visual Studio 2019 v142 platform
        if args.backend == 'vs2017' and args.xp:
            xp_compat(r2_builddir)
        if not args.project:
            project = os.path.join(r2_builddir, 'radare2.sln')
            params = ['/m', '/clp:Summary;Verbosity=minimal']
            if args.backend == 'vs2017' and args.xp:
                params.append('/p:XPDeprecationWarning=false')
            msbuild(project, *params)
    else:
        ninja(r2_builddir)

def install(args):
    """ Install radare2 """
    meson('install', options=['-C', '{}'.format(args.dir), '--no-rebuild'])

def main():
    # Create logger and get applications paths
    set_global_variables()

    # Create parser
    parser = argparse.ArgumentParser(description='Mesonbuild scripts for radare2')
    # --sanitize=address,signed-integer-overflow for faster build
    parser.add_argument('--sanitize', nargs='?',
            const='address,undefined,signed-integer-overflow', metavar='sanitizers',
            help='Build radare2 with sanitizer support (default: %(const)s)')
    parser.add_argument('--project', action='store_true',
            help='Create a visual studio project and do not build.')
    parser.add_argument('--release', action='store_true',
            help='Set the build as Release (remove debug info)')
    parser.add_argument('--backend', choices=BACKENDS, default='ninja',
            help='Choose build backend (default: %(default)s)')
    parser.add_argument('--shared', action='store_true',
            help='Link dynamically (shared library) rather than statically')
    parser.add_argument('--local', action='store_true',
            help='Adds support for local/side-by-side installation (sets rpath if needed)')
    parser.add_argument('--prefix', default=None,
            help='Set project installation prefix')
    parser.add_argument('--dir', default=BUILDDIR, required=False,
            help='Destination build directory (default: %(default)s)')
    parser.add_argument('--alias', action='store_true',
            help='Show the "m" alias shell command')
    parser.add_argument('--xp', action='store_true',
            help='Adds support for Windows XP')
    parser.add_argument('--pull', action='store_true',
            help='git pull before building')
    parser.add_argument('--nosudo', action='store_true',
            help='Do not use sudo for install/symstall/uninstall')
    parser.add_argument('--uninstall', action='store_true',
            help='Uninstall')
    parser.add_argument('--symstall', action='store_true',
            help='Install using symlinks')
    parser.add_argument('--webui', action='store_true',
            help='Install WebUIs')
    parser.add_argument('--install', action='store_true',
            help='Install radare2 after building')
    parser.add_argument('--options', nargs='*', default=[])
    args = parser.parse_args()
    if args.alias:
        print("alias m=\"" + os.path.abspath(__file__) + "\"")
        sys.exit(0);
    if args.sanitize:
        if os.uname().sysname == 'OpenBSD':
            log.error("Sanitizers unsupported under OpenBSD")
            sys.exit(1)
        cflags = os.environ.get('CFLAGS')
        if not cflags:
            cflags = ''
        os.environ['CFLAGS'] = cflags + ' -fsanitize=' + args.sanitize
        if os.uname().sysname != 'Darwin':
          ldflags = os.environ.get('LDFLAGS')
          if not ldflags:
              ldflags = ''
          os.environ['LDFLAGS'] = ldflags + ' -fsanitize=' + args.sanitize

    # Check arguments
    if args.pull:
        os.system('git pull')
    if args.project and args.backend == 'ninja':
        log.error('--project is not compatible with --backend ninja')
        sys.exit(1)
    if args.xp and args.backend in 'ninja':
        log.error('--xp is not compatible with --backend ninja')
        sys.exit(1)
    if args.xp and args.backend in 'vs2019':
        log.error('--xp is not compatible with --backend vs2019')
        sys.exit(1)
    if not args.prefix:
        args.prefix = os.path.join(ROOT, args.dir, 'priv_install_dir')
    else:
        args.prefix = os.path.abspath(args.prefix)
    for option in args.options:
        if '=' not in option:
            log.error('Invalid option: %s', option)
            sys.exit(1)
        key, value = option.split('=', 1)
        key = key.upper()
        if key not in R2_PATH:
            continue
        if os.path.isabs(value):
            log.error('Relative path is required: %s', option)
            sys.exit(1)
        R2_PATH[key] = os.path.normpath(value)

    PATH_FMT.update(R2_PATH)

    sudo = 'sudo '
    if args.nosudo:
        sudo = ''
    # Build it!
    log.debug('Arguments: %s', args)
    build(args)
    if args.uninstall:
        os.system(sudo + 'make uninstall PWD="$PWD/build" BTOP="$PWD/build/binr"')
    if args.install:
        install(args)
    if args.symstall:
        os.system(sudo + 'make symstall PWD="$PWD/build" BTOP="$PWD/build/binr"')

if __name__ == '__main__':
    main()
