#!/bin/sh

# based on
# http://blog.coolaj86.com/articles/how-to-unpackage-and-repackage-pkg-osx.html

# to uninstall:
# sudo pkgutil --forget org.radare.radare2

SRC=/tmp/r2osx
DST="$(pwd)/sys/osx-pkg/radare2.unpkg"
VERSION=0.10.0

rm -rf "${SRC}"
make mrproper
./configure --prefix=/usr || exit 1
make -j4 || exit 1
# TODO: run sys/install.sh
make install PREFIX=/usr DESTDIR=${SRC} || exit 1
if [ -d "${SRC}" ]; then
	(
		cd ${SRC} && \
		find . | cpio -o --format odc | gzip -c > "${DST}/Payload"
	)
	mkbom ${SRC} "${DST}/Bom"

	# Repackage

	pkgutil --flatten "${DST}" "${DST}/../radare2-${VERSION}.pkg"
else
	echo "Failed install. DESTDIR is empty"
	exit 1
fi
