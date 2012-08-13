#!/bin/sh

MAKE_JOBS=8

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd `dirname $PWD/$0` ; cd ..

ccache --help > /dev/null 2>&1
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi

# build
${MAKE} mrproper > /dev/null 2>&1
[ "`uname`" = Linux ] && export LDFLAGS="-Wl,--as-needed"
./configure --prefix=/usr || exit 1
exec ${MAKE} -j ${MAKE_JOBS}
