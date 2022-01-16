#!/bin/sh
# to uninstall:
# sudo pkgutil --forget org.radare.radare2

sys/osx-pkg.sh || exit 1
cp -f sys/osx-pkg/radare2*.pkg dist/macos
exit $?
