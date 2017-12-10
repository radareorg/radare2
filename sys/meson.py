## Meson build for radare2

import argparse
import inspect
import logging
import os

from mesonbuild import mesonmain

ROOT = None
log = None

def setGlobalVariables():
    """ Set global variables """
    global log
    global ROOT

    ROOT = os.path.abspath(inspect.getfile(inspect.currentframe()) + os.path.join(os.path.pardir, os.path.pardir, os.path.pardir))

    logging.basicConfig(format='[Meson][%(levelname)s]: %(message)s', level=logging.DEBUG)
    log = logging.getLogger('r2-meson')

def meson(args):
    """ meson.py equivalent """
    launcher = os.path.realpath(ROOT)
    return mesonmain.run(args, launcher)

def build_r2():
    """ Build radare2 """
    log.info('Building radare2')

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
    # Create logger and get root directory
    setGlobalVariables()
    # Create parser
    parser = argparse.ArgumentParser(description='Mesonbuild scripts for radare2')
    args = parser.parse_args()
    build()

if __name__ == '__main__':
    main()
