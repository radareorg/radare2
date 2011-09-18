#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

# update
if [ -d .hg ]; then
	hg pull -u
elif [ -d .git ]; then
	git pull
fi

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
make -j 4 && \
sudo make symstall
