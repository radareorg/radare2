#!/bin/sh

PREFIX="/data/data/org.radare.installer/radare2"
if [ -z "${NDK}" ]; then
	echo "use ./android-shell.sh"
	exit 1
fi

cd `dirname $PWD/$0` ; cd ..

case "$1" in
"mips")
	NDK_ARCH=mips
	STATIC_BUILD=0
	STRIP=mips-linux-android-strip
echo "FUN"
	;;
"arm")
	NDK_ARCH=arm
	STATIC_BUILD=0
	STRIP=arm-eabi-strip
	;;
"x86")
	NDK_ARCH=x86
	STATIC_BUILD=0
	STRIP=strip
	;;
arm-static|static-arm)
	NDK_ARCH=arm
	STATIC_BUILD=1
	;;
x86-static|static-x86)
	NDK_ARCH=x86
	STATIC_BUILD=1
	;;
mips-static|static-mips)
	NDK_ARCH=mips
	STATIC_BUILD=1
	;;
""|"-h")
	echo "Usage: android-build.sh [arm|x86|mips][-static]"
	exit 1
	;;
*)
	echo "Unknown argument"
	exit 1
	;;
esac

[ -z "${NDK_ARCH}" ] && NDK_ARCH=arm
[ -z "${STATIC_BUILD}" ] && STATIC_BUILD=0
export NDK_ARCH
export STATIC_BUILD
echo NDK_ARCH: ${NDK_ARCH}

echo "Using NDK_ARCH: ${NDK_ARCH}"
echo "Using STATIC_BUILD: ${STATIC_BUILD}"
sleep 2

make mrproper
if [ $STATIC_BUILD = 1 ]; then
	CFGFLAGS="--without-pic --with-nonpic"
fi
./configure --with-compiler=android --with-ostype=android \
	--without-ewf --without-ssl --prefix=${PREFIX} ${CFGFLAGS} || exit 1
make -j 4 || exit 1
PKG=`./configure --version|head -n1 |cut -d ' ' -f 1`
D=${PKG}-android-${NDK_ARCH}
rm -rf $D
mkdir -p $D

INSTALL_PROGRAM=`grep INSTALL_DATA config-user.mk|cut -d = -f 2`

make install INSTALL_PROGRAM="${INSTALL_PROGRAM}" DESTDIR=$PWD/$D || exit 1

make purge-dev DESTDIR=${PWD}/${D} STRIP="${STRIP}"
make purge-doc DESTDIR=${PWD}/${D} STRIP="${STRIP}"

# TODO: remove unused files like include files and so on
cd $D
tar czvf ../$D.tar.gz *
echo "${D}.tar.gz"
