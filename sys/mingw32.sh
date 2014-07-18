#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

CFGFLAGS="--without-ewf --with-ostype=windows"

type i686-pc-mingw32-gcc >/dev/null 2>&1
if [ $? = 0 ]; then
	C=i686-pc-mingw32-gcc
	H=i686-unknown-windows
elif [ -x /usr/bin/i686-w64-mingw32-gcc ]; then
	C=i686-w64-mingw32-gcc
	H=i686-unknown-windows
elif [ -x /usr/bin/pacman ]; then
	C=i486-mingw32-gcc
	H=i486-unknown-windows
elif [ `uname` = Darwin ]; then
	C=i386-mingw32-gcc
	H=i386-unknown-windows
elif [ -x /usr/bin/apt-get ]; then
	C=i586-mingw32msvc-gcc
	H=i586-unknown-windows
else
	echo "arch/opensuse/ubuntu/debian mingw32 package required."
	exit 1
fi

make mrproper

./configure ${CFGFLAGS} --with-compiler=$C --host=$H && \
	make -s -j ${MAKE_JOBS} CC="${C} -static-libgcc" && \
	make w32dist
