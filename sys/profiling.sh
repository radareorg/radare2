#!/bin/sh
export CFLAGS="-O1 -g -ggdb"
#-pg -g -O1"
export CC=clang
export LDFLAGS="$CFLAGS"
#sys/install.sh
if [ -d bpg ];then
	meson setup bpg --reconfigure
else
	meson setup bpg
fi
ninja -C bpg
