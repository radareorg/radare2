## Meson build for radare2

import argparse
import inspect
import logging
import os
import sys

from mesonbuild import mesonmain

ROOT = None
BUILDDIR = 'build'
MESON = None
PYTHON = None
log = None

def setGlobalVariables():
    """ Set global variables """
    global log
    global ROOT
    global MESON
    global PYTHON

    if os.name == 'posix':
        MESON = os.popen('which meson').read().strip()
    else:
        MESON = os.popen('where meson.py').read().strip()

    PYTHON = sys.executable

    ROOT = os.path.abspath(inspect.getfile(inspect.currentframe()) + os.path.join(os.path.pardir, os.path.pardir, os.path.pardir))

    logging.basicConfig(format='[Meson][%(levelname)s]: %(message)s', level=logging.DEBUG)
    log = logging.getLogger('r2-meson')

def build_sdb():
    print('SDB TODO')

def meson(root, build):
    """ Start meson build (i.e. python meson.py ./ build) """
    os.system('{python} {meson} {source} {build}'.format(python=PYTHON, meson=MESON, source=root, build=build))

def ninja(folder):
    """ Start ninja build (i.e. ninja -C build) """
    os.system('ninja -C {}'.format(os.path.join(ROOT, BUILDDIR)))

def build_r2():
    """ Build radare2 """
    log.info('Building radare2')
    if not os.path.exists(BUILDDIR):
        meson(ROOT, BUILDDIR)
    ninja(BUILDDIR)

def build():
    """ Prepare requirements and build radare2 """
    # Prepare capstone
    capstone_path = os.path.join(ROOT, 'shlr', 'capstone')
    if not os.path.isdir(capstone_path):
        log.info('Cloning capstone')
        os.system('git clone -b next --depth 10 https://github.com/aquynh/capstone.git {capstone_path}'.format(capstone_path=capstone_path))

    # Build radare2
    build_r2()

def main():
    # Create logger and get applications paths
    setGlobalVariables()
    # Create parser
    parser = argparse.ArgumentParser(description='Mesonbuild scripts for radare2')
    args = parser.parse_args()
    build()

if __name__ == '__main__':
    main()
