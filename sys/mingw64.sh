#!/bin/sh
cp -f dist/plugins-cfg/plugins.mingw.cfg plugins.cfg
export CC=x86_64-w64-mingw32-gcc
export CFLAGS="-pthread"

./configure --with-ostype=windows --with-compiler=x86_64-w64-mingw32-gcc --prefix=/ || exit 1
make -j4 || exit 1
# install
rm -rf prefix
make install DESTDIR=$PWD/prefix || exit 1
D="radare2-`./configure -qV`-mingw64"
rm -rf "$D"
mkdir -p $D || exit 1
cp -f prefix/bin/*.exe "$D"
cp -f prefix/lib/*.dll "$D"
ls -l "$D"
zip -r "$D.zip" "$D" || exit 1
