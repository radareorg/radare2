#!/bin/sh
PREFIX="$1"
if [ -z "${PREFIX}" ]; then
	PREFIX=/usr
fi
[ -z "${SUDO}" ] && SUDO=sudo
echo "Uninstalling r2 from ${PREFIX}..."
./configure --prefix="${PREFIX}"
${SUDO} make purge
