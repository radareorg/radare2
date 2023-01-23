#!/bin/sh
if [ ! -d .git ]; then
	echo "Run this script from the root of a git copy"
	exit 1
fi
if [ ! -x sys/tarball.sh ]; then
	echo "Run this script from the radare2 root directory"
	exit 1
fi
V=`./configure -qV`
git clone . radare2-${V}
cd radare2-${V}
./preconfigure
git status .
rm -rf .git
find * | grep /.git$ | xargs rm -rf
rm -f .test.c
rm -f config-user.mk
rm -f pkgcfg/*.pc
rm -f libr/include/r_userconf.h
mkdir shlr/capstone/.git
cd ..
rm -f radare2-${V}.tar.xz
tar cJvf radare2-${V}.tar.xz radare2-${V}
rm -f radare2-${V}.zip
zip -r radare2-${V}.zip radare2-${V}
rm -rf radare2-${V}
