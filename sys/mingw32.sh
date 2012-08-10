#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

if [ -x /usr/bin/pacman ]; then
	make clean
	./configure --without-gmp --with-compiler=i486-mingw32-gcc --with-ostype=windows --host=i486-unknown-windows --without-ssl && \
	make -j ${MAKE_JOBS} && \
	make w32dist
elif [ `uname` = Darwin ]; then
	make clean
	./configure --without-gmp --with-compiler=i386-mingw32-gcc --with-ostype=windows --host=i386-unknown-windows --without-ssl && \
	make -j ${MAKE_JOBS} && \
	make w32dist
elif [ -x /usr/bin/apt-get ]; then
	make clean
	./configure --without-gmp --with-compiler=i586-mingw32msvc-gcc  --with-ostype=windows --host=i586-unknown-windows && \
	make -j ${MAKE_JOBS} && \
	make w32dist
else
	echo "ubuntu/debian or archlinux required."
	exit 1
fi
