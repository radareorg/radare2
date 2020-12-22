#!/bin/sh

rm -rf shlr/capstone
make mrproper
cp -f plugins.static.nogpl.cfg plugins.cfg
./configure --prefix=/usr --with-libr
make -j4
