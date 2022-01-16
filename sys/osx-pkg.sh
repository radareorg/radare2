#!/bin/sh

# BasedOn: http://blog.coolaj86.com/articles/how-to-unpackage-and-repackage-pkg-osx.html
# Also: https://gist.github.com/SchizoDuckie/2a1a1cc71284e6463b9a

# to uninstall:
# sudo pkgutil --forget org.radare.radare2

SRC=/tmp/r2osx
PREFIX=/usr/local
DST="$(pwd)/sys/osx-pkg/radare2.unpkg"
if [ -n "$1" ]; then
	VERSION="$1"
else
	# VERSION="`./configure --version| head -n 1|awk '{print $1}'|cut -d - -f 2`"
	VERSION="`./configure -qV`"
	[ -z "${VERSION}" ] && VERSION=`r2 -qv`
	[ -z "${VERSION}" ] && VERSION=5.4.0
fi
[ -z "${MAKE}" ] && MAKE=make

rm -rf "${SRC}"
${MAKE} mrproper 2>/dev/null
export CFLAGS="-O2"
./configure --prefix="${PREFIX}" --without-libuv || exit 1
${MAKE} -j4 || exit 1
# TODO: run sys/install.sh
${MAKE} install PREFIX="${PREFIX}" DESTDIR=${SRC} || exit 1
if [ -d "${SRC}" ]; then
	(
		cd ${SRC} && \
		find . | cpio -o --format odc | gzip -9 -c > "${DST}/Payload"
	)
	mkbom ${SRC} "${DST}/Bom"
	# Repackage
	pkgutil --flatten "${DST}" "${DST}/../radare2-${VERSION}.pkg"
else
	echo "Failed install. DESTDIR is empty"
	exit 1
fi
