#!/bin/sh
# to uninstall:
# sudo pkgutil --forget org.radare.radare2

sys/osx-pkg.sh || exit 1
cp -f sys/osx-pkg/radare2*.pkg dist/macos
exit $?

SRC=/tmp/r2osx
PREFIX=/usr/local
DST="$(pwd)/sys/osx-pkg/radare2.unpkg"
if [ -n "$1" ]; then
	VERSION="$1"
else
	VERSION="`./configure -qV`"
fi
[ -z "${VERSION}" ] && echo "Unknown version" && exit 1
[ -z "${MAKE}" ] && MAKE=make

rm -rf "${SRC}"
${MAKE} mrproper 2>/dev/null
export CFLAGS=-O2
./configure --prefix="${PREFIX}" --without-libuv || exit 1
${MAKE} -j4 || exit 1
# TODO: run sys/install.sh
${MAKE} macos-sign
${MAKE} install PREFIX="${PREFIX}" DESTDIR=${SRC} || exit 1
if [ -d "${SRC}" ]; then
	(
		cd "${SRC}" && \
		find . | cpio -o --format odc | gzip -c > "${DST}/Payload"
	)
	echo mkbom "${SRC}" "${DST}/Bom"
	mkbom "${SRC}" "${DST}/Bom"
	# Repackage
	echo pkgutil --flatten "${DST}" "${DST}/../radare2-${VERSION}.pkg"
	pkgutil --flatten "${DST}" "${DST}/../radare2-${VERSION}.pkg"
else
	echo "Failed install. DESTDIR is empty"
	exit 1
fi
