#!/bin/sh

if [ -x /usr/bin/pacman ]; then
	make clean
	./configure --without-gmp --with-compiler=i486-mingw32-gcc --with-ostype=windows --host=i486-unknown-windows --without-ssl && \
	make && \
	make w32dist
elif [ -x /usr/bin/apt-get ]; then
	./configure --without-gmp --with-compiler=i586-mingw32msvc-gcc  --with-ostype=windows --host=i586-unknown-windows && \
	make && \
	make w32dist
else
	echo "ubuntu/debian or archlinux required."
	exit 1
fi
