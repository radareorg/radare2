#!/bin/sh

# find root
cd `dirname $PWD/$0`
./clone-r2-bindings.sh
cd ..

[ -z "${PREFIX}" ] && PREFIX=/usr
ID=`id -u` 
[ -n "${NOSUDO}" ] && SUDO=

export DESTDIR

cd radare2-bindings
./configure --prefix=/usr --enable=duktape
cd libr/lang/p
make clean
make
rm ~/.config/radare2/plugins/lang_duktape.*
if [ "$1" != '--no-install' ]; then
	if [ "$ID" = 0 ]; then
		${SUDO} make install DESTDIR=${DESTDIR}
	else
		make install-home
	fi
fi
