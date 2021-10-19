#!/bin/sh
rm -f plugins.cfg
cp -f dist/plugins-cfg/plugins.mingw.cfg plugins.cfg
./configure --with-ostype=windows --with-compiler=i686-w64-mingw32-gcc --prefix=/
make -j4
