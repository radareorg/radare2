#!/bin/sh
cp -f dist/plugins-cfg/plugins.mingw.cfg plugins.cfg
export CC=x86_64-w64-mingw32-gcc
./configure --with-ostype=windows --with-compiler=x86_64-w64-mingw32-gcc --prefix=/ --without-libuv
make -j4
# install
rm -rf prefix
make install DESTDIR=$PWD/prefix
cp -f prefix/lib/*.dll prefix/bin/
D=radare2-`./configure -qV`-mingw32
rm -rf $D
mkdir -p $D
cp -rf prefix/bin/*.exe $D
cp -rf prefix/lib/*.dll $D
zip -r $D.zip $D
