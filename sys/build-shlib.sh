#!/bin/sh

make mrproper
cp -f dist/plugins-cfg/plugins.static.nogpl.cfg plugins.cfg
./configure --prefix=/usr --with-libr
make -j4
