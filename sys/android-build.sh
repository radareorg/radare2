#!/bin/sh

cd `dirname $PWD/$0` ; cd ..

[ -z "${NDK_ARCH}" ] && NDK_ARCH=x86
[ -z "${STATIC_BUILD}" ] && STATIC_BUILD=0
export NDK_ARCH
export STATIC_BUILD

if [ 0 = 1 ]; then
make clean
if [ $STATIC_BUILD = 1 ]; then
CFGFLAGS="--without-pic --with-nonpic"
fi
./configure --with-compiler=android --with-ostype=android \
	--without-ssl --prefix=/data/radare2 ${CFGFLAGS}
make -j 4
fi
PKG=`./configure --version|head -n1 |cut -d ' ' -f 1`
D=${PKG}-android-${NDK_ARCH}
rm -rf $D
mkdir -p $D
make install DESTDIR=$PWD/$D
# TODO: remove unused files like include files and so on
cd $D
tar czvf ../$D.tar.gz *
echo "${D}.tar.gz"
