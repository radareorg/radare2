#!/bin/sh

# find root
cd `dirname $PWD/$0` ; cd ..

export PATH=${PWD}/sys/_work/mingw64/bin:${PATH}

make clean
./configure --without-gmp --with-compiler=x86_64-w64-mingw32-gcc --with-ostype=windows --host=x86_64-unknown-windows --without-ssl
make
make w32dist
