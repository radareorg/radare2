#!/bin/sh

MAKE_JOBS=8

# find root
cd "$(dirname "$PWD/$0")" ; cd ..

export PATH=${PWD}/sys/_work/mingw64/bin:${PATH}
# TODO: add support for ccache

type x86_64-w64-mingw32-gcc >/dev/null 2>&1
if [ $? = 0 ]; then
	C=x86_64-w64-mingw32-gcc
else
	echo "mingw64 package required."
	exit 1
fi

make clean
./configure --without-gmp --with-compiler=x86_64-w64-mingw32-gcc --with-ostype=windows --host=x86_64-unknown-windows --without-ssl
make -s -j ${MAKE_JOBS} CC="${C} -static-libgcc" && \
make w64dist
