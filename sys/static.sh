#!/bin/sh

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
if [ -f config-user.mk ]; then
	${MAKE} mrproper > /dev/null 2>&1
fi
./configure-plugins
./configure --prefix=/usr --without-ewf --with-nonpic --without-pic && \
${MAKE} -j 4
