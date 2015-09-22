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

# Required to build on FreeBSD
if [ ! -x /usr/bin/gcc -a -x /usr/bin/cc ]; then
	export CC=cc
	export HOST_CC=cc
fi

echo
echo "export USE_R2_CAPSTONE=$USE_R2_CAPSTONE"
echo
# Set USE_R2_CAPSTONE env var to ignore syscapstone check
if [ -z "${USE_R2_CAPSTONE}" ]; then
	pkg-config --atleast-version=3.0 capstone 2>/dev/null
	if [ $? = 0 ]; then
		echo '#include <capstone.h>' > .a.c
		echo 'int main() {return 0;}' >> .a.c
		gcc `pkg-config --cflags --libs capstone` -o .a.out .a.c
		if [ $? = 0 ]; then
			CFGARG="${CFGARG} --with-syscapstone"
		else
			echo
			echo "** WARNING ** capstone pkg-config is wrongly installed."
			echo
		fi
		rm -f .a.c .a.out
	fi
fi

# build
${MAKE} mrproper > /dev/null 2>&1
if [ -d shlr/capstone/.git ]; then
( cd shlr/capstone ; git clean -xdf )
fi
[ "`uname`" = Linux ] && export LDFLAGS="-Wl,--as-needed ${LDFLAGS}"
rm -f plugins.cfg
./configure ${CFGARG} --prefix=${PREFIX} || exit 1
${MAKE} -s -j${MAKE_JOBS} MAKE_JOBS=${MAKE_JOBS} || exit 1
if [ "`uname`" = Darwin ]; then
	${MAKE} osx-sign osx-sign-libs CERTID="${CERTID}" || (
		echo "CERTID not defined. If you want the bins signed to debug without root"
		echo "follow the instructions described in doc/osx and run make osx-sign."
	)
fi
