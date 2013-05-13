#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

CFGFLAGS="--without-ewf --with-ostype=windows"

if [ -x /usr/bin/pacman ]; then
	make clean
	./configure ${CFGFLAGS} --with-compiler=i486-mingw32-gcc --host=i486-unknown-windows && \
	make -s -j ${MAKE_JOBS} && \
	make w32dist
elif [ `uname` = Darwin ]; then
	make clean
	./configure ${CFGFLAGS} --with-compiler=i386-mingw32-gcc --host=i386-unknown-windows && \
	make -s -j ${MAKE_JOBS} && \
	make w32dist
elif [ -x /usr/bin/apt-get ]; then
	make clean
	./configure ${CFGFLAGS} --with-compiler=i586-mingw32msvc-gcc --host=i586-unknown-windows && \
	make -s -j ${MAKE_JOBS} && \
	make w32dist
else
	echo "ubuntu/debian or archlinux required."
	exit 1
fi
