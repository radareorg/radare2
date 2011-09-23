#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

if [ -x /usr/bin/pacman ]; then
	make clean
	./configure --without-gmp --with-compiler=i486-mingw32-gcc --with-ostype=windows --host=i486-unknown-windows --without-ssl && \
	make -j 4 && \
	make w32dist
elif [ `uname` = Darwin ]; then
	make clean
	./configure --without-gmp --with-compiler=i386-mingw32-gcc --with-ostype=windows --host=i386-unknown-windows --without-ssl && \
	make -j 4 && \
	make w32dist
elif [ -x /usr/bin/apt-get ]; then
	make clean
	./configure --without-gmp --with-compiler=i586-mingw32msvc-gcc  --with-ostype=windows --host=i586-unknown-windows && \
	make -j 4 && \
	make w32dist
else
	echo "ubuntu/debian or archlinux required."
	exit 1
fi
