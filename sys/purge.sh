#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake


PREFIX="$1"
if [ -z "${PREFIX}" ]; then
	PREFIX=/usr
fi
[ -z "${SUDO}" ] && SUDO=sudo
echo "Uninstalling r2 from ${PREFIX}..."
./configure --prefix="${PREFIX}"
${SUDO} ${MAKE} purge
