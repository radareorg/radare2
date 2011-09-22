#!/bin/sh

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
	make mrproper
fi
./configure --prefix=/usr && \
make -j 4
