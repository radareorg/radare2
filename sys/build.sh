#!/bin/sh

MAKE_JOBS=12
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
	CFGARG="${CFGARG} --with-rpath"

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

pkg-config --atleast-version=3.0 capstone 2>/dev/null
if [ $? = 0 ]; then
	CFGARG="${CFGARG} --with-syscapstone"
fi

# build
${MAKE} mrproper > /dev/null 2>&1
if [ -d shlr/capstone/.git ]; then
( cd shlr/capstone ; git clean -xdf )
fi
[ "`uname`" = Linux ] && export LDFLAGS="-Wl,--as-needed ${LDFLAGS}"
rm -f plugins.cfg
./configure ${CFGARG} --prefix=${PREFIX} || exit 1
exec ${MAKE} -s -j${MAKE_JOBS} MAKE_JOBS=${MAKE_JOBS}
