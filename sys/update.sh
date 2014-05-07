#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

# update
if [ -d .git ]; then
	git pull
fi

ccache --help 2>&1 > /dev/null
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi

# build
./configure --prefix=/usr && \
make -j 4 && \
sudo make symstall
