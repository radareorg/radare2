#!/bin/sh

MAKE_JOBS=8
[ -z "${PREFIX}" ] && PREFIX=/usr

case "$1" in
-h)
	echo "Usage: sys/build.sh [/usr]"
	exit 0
	;;
'')
	:
	;;
*)
	PREFIX="$1"
	;;
esac

[ ! "${PREFIX}" = /usr ] && \
	CFGARG=--with-rpath

if [ -z "${MAKE}" ]; then
	MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

# find root
cd `dirname $PWD/$0` ; cd ..

ccache --help > /dev/null 2>&1
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi

# build
echo "Cleaning up the whole thing..."
${MAKE} mrproper > /dev/null 2>&1
[ "`uname`" = Linux ] && export LDFLAGS="-Wl,--as-needed"
rm -f plugins.cfg
# STATIC BUILD
CFLAGS="${CFLAGS} -m32"
export CFLAGS

./configure ${CFGARG} --prefix=${PREFIX} || exit 1
exec ${MAKE} -s -j ${MAKE_JOBS}
