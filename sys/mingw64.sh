#!/bin/sh

# find root
cd `dirname $(pwd)/$0` ; cd ..

export PATH=$(pwd)/sys/_work/mingw64/bin:${PATH}
# TODO: add support for ccache

make clean
./configure --without-gmp --with-compiler=x86_64-w64-mingw32-gcc --with-ostype=windows --host=x86_64-unknown-windows --without-ssl
make -j 4
make w32dist
