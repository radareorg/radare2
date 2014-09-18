#!/bin/sh

# based on
# http://blog.coolaj86.com/articles/how-to-unpackage-and-repackage-pkg-osx.html

# to uninstall:
# sudo pkgutil --forget org.radare.radare2

SRC=/tmp/r2osx
DST=`pwd`/sys/osx-pkg/radare2.unpkg

rm -rf ${SRC}
make mrproper
./configure --prefix=/usr/local
make -j4
# TODO: run sys/install.sh
make install PREFIX=/usr DESTDIR=${SRC}
(
cd ${SRC}
find . | cpio -o --format odc | gzip -c > ${DST}/Payload
)
mkbom ${SRC} ${DST}/Bom

# Repackage

pkgutil --flatten ${DST} ${DST}/../radare2.pkg
