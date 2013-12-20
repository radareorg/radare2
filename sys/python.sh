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

export PYTHON
export DESTDIR
export PYTHON_VERSION
export PYTHON_CONFIG
echo "Using PYTHON_VERSION ${PYTHON_VERSION}"
PYTHON_CONFIG="python${PYTHON_VERSION}-config"
echo "Using PYTHON_CONFIG ${PYTHON_CONFIG}"
echo

cd radare2-bindings
./configure --prefix=${PREFIX} --enable=python || exit 1
${SUDO} make install-vapi DESTDIR=${DESTDIR} || exit 1
cd python
make clean
make PYTHON=${PYTHON}
[ "$1" != '--no-install' ] && \
	${SUDO} make install PYTHON=${PYTHON} \
	PYTHON_VERSION=${PYTHON_VERSION} DESTDIR=${DESTDIR}
