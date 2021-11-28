#!/bin/sh
cp -f dist/plugins-cfg/plugins.mingw.cfg plugins.cfg
export CC=x86_64-w64-mingw32-gcc
./configure --with-ostype=windows --with-compiler=x86_64-w64-mingw32-gcc --prefix=/ --without-libuv
make -j4
