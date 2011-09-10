#!/bin/sh

make clean
./configure --without-gmp --with-compiler=x86_64-w64-mingw32-gcc --with-ostype=windows --host=x86_64-unknown-windows --without-magic --without-ssl
make
make w32dist
