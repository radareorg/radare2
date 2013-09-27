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
rm -f plugins.cfg
# STATIC BUILD
CFLAGS="${CFLAGS} -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2"
CFGFLAGS="--without-pic --with-nonpic"
export CFLAGS

# TODO: add this?
#LDFLAGS="${LDFLAGS} -Wl,-z,now -Wl,-z,relro"
#export LDFLAGS
./configure ${CFGARG} --prefix=${PREFIX} || exit 1
exec ${MAKE} -s -j ${MAKE_JOBS}
