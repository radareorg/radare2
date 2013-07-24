#!/bin/sh

BUILD=1
PREFIX="/data/data/org.radare.installer/radare2"
WD=$(pwd)
if [ -z "${NDK}" ]; then
	echo "use ./android-{arm|mips|x86}.sh"
	exit 1
fi

cd `dirname $(pwd)/$0` ; cd ..

case "$1" in
"mips")
	NDK_ARCH=mips
	STATIC_BUILD=0
	STRIP=mips-linux-android-strip
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
	# XXX: by default we should build all libs as .a but link binary dinamically
	STATIC_BUILD=1
	STRIP=mips-linux-android-strip
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

# ow yeah
STATIC_BUILD=1
export NDK_ARCH
export STATIC_BUILD
PKG=`./configure --version|head -n1 |cut -d ' ' -f 1`
D=${PKG}-android-${NDK_ARCH}
echo NDK_ARCH: ${NDK_ARCH}

echo "Using NDK_ARCH: ${NDK_ARCH}"
echo "Using STATIC_BUILD: ${STATIC_BUILD}"

if [ "${BUILD}" = 1 ]; then
# start build
sleep 2

make mrproper
if [ $STATIC_BUILD = 1 ]; then
	CFGFLAGS="--without-pic --with-nonpic"
fi
# dup
echo ./configure --with-compiler=android \
	--with-ostype=android --without-ewf \
	--prefix=${PREFIX} ${CFGFLAGS}

./configure --with-compiler=android --with-ostype=android \
	--without-ewf --prefix=${PREFIX} ${CFGFLAGS} || exit 1
make -s -j 4 || exit 1
fi
rm -rf $D
mkdir -p $D

INSTALL_PROGRAM=`grep INSTALL_DATA config-user.mk|cut -d = -f 2`

make install INSTALL_PROGRAM="${INSTALL_PROGRAM}" DESTDIR=$PWD/$D || exit 1

make purge-dev DESTDIR=${WD}/${D} STRIP="${STRIP}"
make purge-doc DESTDIR=${WD}/${D} STRIP="${STRIP}"
rm -rf ${WD}/${D}/share
rm -rf ${WD}/${D}/include
rm -rf ${WD}/${D}/lib/pkgconfig
rm -rf ${WD}/${D}/lib/libsdb.a

echo rm -rf ${WD}/${D}/${PREFIX}/bin/*
rm -rf ${WD}/${D}/${PREFIX}/bin/*

#end build

# use busybox style symlinkz
HERE=${WD}
cd binr/blob
make STATIC_BUILD=1
make install PREFIX="${PREFIX}" DESTDIR="${HERE}/${D}"
cd ../..

chmod +x ${WD}/${D}/${PREFIX}/bin/*

# TODO: remove unused files like include files and so on
rm -f ${WD}/${D}/${PREFIX}/lib/radare2/*/*.so \
	${WD}/${D}/${PREFIX}/lib/*.a
rm -rf ${WD}/${D}/${PREFIX}/include \
	${WD}/${D}/${PREFIX}/share \
	${WD}/${D}/${PREFIX}/doc
eval `grep ^VERSION= ${WD}/config-user.mk`
WWWROOT="/data/data/org.radare.installer/radare2/lib/radare2/${VERSION}/www"
ln -fs /data/data/org.radare.installer/radare2/${WWWROOT} \
	/data/data/org.radare.installer/www
cd $D
tar czvf ../$D.tar.gz *
cd ..
D2=`git log HEAD 2>/dev/null|head -n1|awk '{print $2}'|cut -c 1-8`
if [ -n "$D2" ]; then
	ln -fs $D.tar.gz "${D}${D2}".tar.gz
fi
echo "${WD}/${D}.tar.gz"
echo "${WD}/${D}${D2}.tar.gz"
