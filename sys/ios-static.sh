#!/bin/sh

if [ -z "${CPU}" ]; then
	export CPU=arm64
	export CPU=armv7
fi

[ -z "${MAKE}" ] && MAKE=make
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=12

# if set to 1 build without fork or debugger support
APPSTORE_FRIENDLY=0

export BUILD=1
PREFIX="/usr"
# PREFIX=/var/mobile

if [ ! -d sys/ios-include ]; then
(
	cd sys && \
	wget http://lolcathost.org/b/ios-include.tar.gz && \
	tar xzvf ios-include.tar.gz
)
fi

export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:$PATH
export PATH=$(pwd)/sys:${PATH}
export CC=$(pwd)/sys/ios-sdk-gcc
# set only for arm64, otherwise it is armv7
# select ios sdk version
export IOSVER=9.3
export IOSINC=$(pwd)/sys/ios-include
export CFLAGS=-O2
export USE_SIMULATOR=0

if [ "${APPSTORE_FRIENDLY}" = 1 ]; then
	CFGFLAGS="--without-fork --without-debugger"
else
	CFGFLAGS=""
fi

if true ; then
${MAKE} clean
cp -f plugins.tiny.cfg plugins.cfg
./configure --prefix="${PREFIX}" \
	${CFGFLAGS} \
	--with-ostype=darwin \
	--without-pic --with-nonpic \
	--with-compiler=ios-sdk \
	--target=arm-unknown-darwin
fi

if [ $? = 0 ]; then
	time ${MAKE} -j${MAKE_JOBS}
	if [ $? = 0 ]; then
		( cd binr/radare2 ; ${MAKE} ios_sdk_sign )
		rm -rf /tmp/r2ios
		${MAKE} install DESTDIR=/tmp/r2ios
		rm -rf /tmp/r2ios/usr/share/radare2/*/www/enyo/node_modules
		( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz ./* )
		rm -rf sys/cydia/radare2/root
		mkdir -p sys/cydia/radare2/root
		sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C sys/cydia/radare2/root
		( cd sys/cydia/radare2 ; sudo ${MAKE} clean ; sudo ${MAKE} )
	fi
fi
