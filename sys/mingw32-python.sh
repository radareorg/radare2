#!/bin/sh
cd `dirname $PWD/$0`
./clone-r2-bindings.sh
cd ../radare2-bindings

type i686-pc-mingw32-gcc >/dev/null 2>&1
if [ $? = 0 ]; then
	C=i686-pc-mingw32-gcc
	G=i686-pc-mingw32-gcc
	H=i686-unknown-windows
elif [ -x /usr/bin/i686-w64-mingw32-gcc ]; then
	C=i686-w64-mingw32-gcc
	H=i686-unknown-windows
	G=i686-w64-mingw32-g++
elif [ -x /usr/bin/pacman ]; then
	C=i486-mingw32-gcc
	H=i486-unknown-windows
	G=i486-mingw32-g++
elif [ `uname` = Darwin ]; then
	C=i386-mingw32-gcc
	H=i386-unknown-windows
	G=i386-mingw32-g++
elif [ -x /usr/bin/apt-get ]; then
	C=i586-mingw32msvc-gcc
	H=i586-unknown-windows
	G=i586-mingw32msvc-g++
else
	echo "mingw32 required in some version, nothing found!"
	exit 1
fi

make clean
./configure --with-cc=$C --with-cxx=$G --enable=python --host=$H --with-ostype=windows --prefix=/usr || exit 1

sudo make install-vapi

make w32 CC=$C CXX=$G || exit 1
make w32dist
