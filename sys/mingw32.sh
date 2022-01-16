#!/bin/sh
cp -f dist/plugins-cfg/plugins.mingw.cfg plugins.cfg
export CC=i686-w64-mingw32-gcc
./configure --with-ostype=windows --with-compiler=i686-w64-mingw32-gcc --prefix=/ --without-libuv || exit 1
make -j4 || exit 1
# install
rm -rf prefix
make install DESTDIR=$PWD/prefix || exit 1
D="radare2-`./configure -qV`-mingw32"
rm -rf "$D"
mkdir -p "$D"
cp -f prefix/bin/*.exe "$D"
cp -f prefix/lib/*.dll "$D"
ls -l "$D"
exec zip -r "$D.zip" "$D"
