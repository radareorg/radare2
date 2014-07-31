#!/bin/sh

# find root
cd `dirname $PWD/$0`
./clone-r2-bindings.sh
cd ..

. ./sys/CONFIG
echo =============
cat sys/CONFIG
echo =============

[ -z "${PREFIX}" ] && PREFIX=/usr
ID=`id -u` 
[ -n "${NOSUDO}" ] && SUDO=

export DESTDIR

cd radare2-bindings
#./configure --prefix=${PREFIX} --enable=duktype || exit 1
cd libr/lang/p
make clean
make
rm ~/.config/radare2/plugins/lang_duktape.*
if [ "$ID" = 0 ]; then
	make install DESTDIR=${DESTDIR}
else
	make install-home
fi
[ "$1" != '--no-install' ] && \
	${SUDO} make install DESTDIR=${DESTDIR}
