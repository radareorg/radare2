#!/bin/sh

# find root
cd `dirname $PWD/$0`
./clone-r2-bindings.sh
cd ..

. ./sys/CONFIG
echo =============
cat sys/CONFIG
echo =============

[ -z "${PREFIX}" ] && PREFIX=/usr
ID=`id -u` 
if [ "$ID" = 0 ]; then
	SUDO=
else
	SUDO=sudo
fi
[ -n "${NOSUDO}" ] && SUDO=

cd radare2-bindings
./configure --prefix=${PREFIX} --enable=lua || exit 1
cd lua
make clean
make
[ ! "$1" = --no-install ] && \
	${SUDO} make install DESTDIR=${DESTDIR}
