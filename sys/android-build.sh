#!/bin/sh

BUILD=1
FLAGS=""
PREFIX="/data/data/org.radare.radare2installer/radare2"
MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

type pax
[ $? != 0 ] && exit 1

cd `dirname $PWD/$0` ; cd ..

# we need a more recent ndk to build the mergedlib for mips

[ -z "${NDK_ARCH}" ] && NDK_ARCH=arm

# ow yeah
STATIC_BUILD=1

case "$1" in
"mips")
	NDK_ARCH=mips
	STATIC_BUILD=0
	STRIP=mips-linux-android-strip
#	FLAGS="-mlong-calls"
#	export LDFLAGS="-fuse-ld=gold"
	;;
"mips64")
	NDK_ARCH=mips64
	STATIC_BUILD=0
	STRIP=mips64el-linux-android-strip
#	FLAGS="-mlong-calls"
#	export LDFLAGS="-fuse-ld=gold"
	;;
arm)
	NDK_ARCH=arm
	STATIC_BUILD=0
	STRIP=arm-eabi-strip
	;;
arm64|aarch64)
	NDK_ARCH=aarch64
	STATIC_BUILD=0
	STRIP=aarch64-linux-android-strip
	;;
x64|x86_64)
	NDK_ARCH=x86_64
	export NDK_ARCH
	STATIC_BUILD=0
	STRIP=strip
	;;
x86)
	NDK_ARCH=x86
	STATIC_BUILD=0
	STRIP=strip
	;;
x64-static|static-x64)
	NDK_ARCH=x86
	STATIC_BUILD=1
	;;
arm64-static|static-arm64)
	NDK_ARCH=aarch64
	STATIC_BUILD=1
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
	# XXX: by default we should build all libs as .a but link binary dynamically
	STATIC_BUILD=1
	STRIP=mips-linux-android-strip
	;;
mips64-static|static-mips64)
	NDK_ARCH=mips64
	# XXX: by default we should build all libs as .a but link binary dynamically
	STATIC_BUILD=1
	STRIP=mips64el-linux-android-strip
	;;
local)
	BUILD=0
	sys/static.sh ${PREFIX}
	NDK_ARCH=local
	;;
""|"-h")
	echo "Usage: android-build.sh [local|arm|arm64|x86|x64|mips|mips64][-static]"
	exit 1
	;;
*)
	echo "Unknown argument"
	exit 1
	;;
esac

[ -z "${STATIC_BUILD}" ] && STATIC_BUILD=0
export NDK_ARCH
export STATIC_BUILD
PKG=`./configure --version|head -n1 |cut -d ' ' -f 1`
D=${PKG}-android-${NDK_ARCH}
echo NDK_ARCH: ${NDK_ARCH}

echo "Using NDK_ARCH: ${NDK_ARCH}"
echo "Using STATIC_BUILD: ${STATIC_BUILD}"

export CFLAGS="-fPIC -fPIE ${FLAGS}"

if [ "${BUILD}" = 1 ]; then
	if [ -z "${NDK}" ]; then
		exec sys/android-shell.sh ${NDK_ARCH} $0 $@
	fi
	export ANDROID=1
	# start build
	sleep 1

	if [ 1 = 1 ]; then
		${MAKE} mrproper
		if [ $STATIC_BUILD = 1 ]; then
			CFGFLAGS="--with-libr"
		fi
		# dup
		echo ./configure --with-compiler=android \
			--with-ostype=android \
			--prefix=${PREFIX} ${CFGFLAGS}
		cp -f plugins.android.cfg plugins.cfg
		./configure --with-compiler=android --with-ostype=android \
			--prefix=${PREFIX} ${CFGFLAGS} || exit 1
		${MAKE} -s -j 4 || exit 1
	fi
fi
rm -rf $D
mkdir -p $D

HERE=${PWD}
INSTALL_PROGRAM=`grep INSTALL_DATA config-user.mk|cut -d = -f 2`

${MAKE} install INSTALL_PROGRAM="${INSTALL_PROGRAM}" DESTDIR="$HERE/$D" || exit 1

${MAKE} purge-dev DESTDIR="${PWD}/${D}" STRIP="${STRIP}"
#make purge-doc DESTDIR=${PWD}/${D} STRIP="${STRIP}"
#rm -rf ${PWD}/${D}/share
rm -rf ${PWD}/${D}/include
rm -rf ${PWD}/${D}/lib/pkgconfig
rm -rf ${PWD}/${D}/lib/libsdb.a
#rm -rf "${HERE}/${D}/${PREFIX}/lib"

rm -rf "${HERE}/${D}/${PREFIX}/radare2" # r2pm
rm -rf "${HERE}/${D}/${PREFIX}/bin/r2pm"
#echo rm -rf ${PWD}/${D}/${BINDIR}/*

#find $HERE/$D | grep www
#sleep 4
#end build

# use busybox style symlinkz
cd binr/blob
#${MAKE} || exit 1
#CFLAGS=-static LDFLAGS=-static ${MAKE} -j4 || exit 1
${MAKE} -j4 || exit 1
${MAKE} install PREFIX="${PREFIX}" DESTDIR="${HERE}/${D}" || exit 1
mkdir -p ${HERE}/${D}/${PREFIX}/projects
:> ${HERE}/${D}/${PREFIX}/projects/.empty
mkdir -p ${HERE}/${D}/${PREFIX}/tmp
:> ${HERE}/${D}/${PREFIX}/tmp/.empty
cd ../..

chmod +x "${HERE}/${D}/${BINDIR}/"*
find ${D}/${DATADIR}/radare2/*/www
# Remove development files
rm -f ${HERE}/${D}/${LIBDIR}/radare2/*/*.so
rm -f ${HERE}/${D}/${LIBDIR}/*.a
rm -rf ${HERE}/${D}/${DATADIR}/radare2/*/www/*/node_modules
rm -rf ${HERE}/${D}/${PREFIX}/include
eval `grep ^VERSION= ${HERE}/config-user.mk`
WWWROOT="/data/data/org.radare.radare2installer/radare2/share/radare2/${VERSION}/www"
WWWWOOT="${HERE}/${D}/data/data/org.radare.radare2installer/www"
WWWSOOT="${HERE}/${D}/data/data/org.radare.radare2installer/radare2/share/radare2/${VERSION}/www"
echo WWWROOT="${WWWROOT}"
echo WWWROOT="${WWWWOOT}"
echo WWWROOT="${WWWSOOT}"
(
	rm -rf "${WWWWOOT}"
	mkdir -p "${WWWWOOT}"
	mv "${WWWSOOT}"/* "${WWWWOOT}"
	# pax doesnt like symlinks when making it compatible with the java tar
	#cd "${WWWWOOT}/.."
	#ln -fs "../radare2/share/radare2/${VERSION}/www" www
	#ln -fs "${WWWROOT}" "${WWWWOOT}"
)
chmod -R o+rx "${WWWWOOT}"
cd ${D}
find $HERE/$D | grep www
sleep 4
#sltar -c data | gzip > ../$D.tar.gz
pax -w data | gzip > ../$D.tar.gz

#	tar --help| grep -q GNU
#	if [ $? = 0 ]; then
#		echo tar -czv -H oldgnu -f ../$D.tar.gz data
#		tar -czv -H oldgnu -f ../$D.tar.gz data
#	else
#		echo tar -czovf ../$D.tar.gz data
#		tar -czovf ../$D.tar.gz data
#	fi

cd ..
D2=`git log HEAD 2>/dev/null|head -n1|awk '{print $2}'|cut -c 1-8`
if [ -n "$D2" ]; then
	ln -fs $D.tar.gz "${D}-${D2}".tar.gz
fi
echo `pwd`"/${D}.tar.gz"
echo `pwd`"/${D}-${D2}.tar.gz"

adb push `pwd`"/${D}-${D2}.tar.gz" /sdcard/radare2-android.tar.gz || true
exit 0
