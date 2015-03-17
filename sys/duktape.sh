#!/bin/sh

# find root
cd `dirname $PWD/$0`
./clone-r2-bindings.sh
cd ..

# workaround for osx
if [ -f /usr/lib/pkgconfig/r_util.pc ]; then
	export PKG_CONFIG_PATH=/usr/lib/pkgconfig
fi
[ -z "${PREFIX}" ] && PREFIX=/usr
ID=`id -u` 
[ -n "${NOSUDO}" ] && SUDO=

export DESTDIR

cd radare2-bindings
./configure --prefix=/usr --enable=duktape || exit 1
cd libr/lang/p
make clean
make || exit 1
rm -f ~/.config/radare2/plugins/lang_duktape.*
if [ "$1" != '--no-install' ]; then
	if [ "$ID" = 0 ]; then
		${SUDO} make install DESTDIR=${DESTDIR}
	else
		make install-home
	fi
fi
