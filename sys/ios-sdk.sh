#!/bin/sh

if [ -z "${CPU}" ]; then
export CPU=arm64
export CPU=armv7
fi

BUILD=1
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
export PATH=`pwd`/sys:${PATH}
export CC=`pwd`/sys/ios-sdk-gcc
# set only for arm64, otherwise it is armv7
# select ios sdk version
export IOSVER=8.1
export IOSINC=`pwd`/sys/ios-include
export CFLAGS=-O2

if true ; then
make clean
./configure --prefix=${PREFIX} --with-ostype=darwin \
	--with-compiler=ios-sdk --target=arm-unknown-darwin \
	--without-libversion --without-ewf
fi

if [ $? = 0 ]; then
	time make -j4
	if [ $? = 0 ]; then
		( cd binr/radare2 ; make ios_sdk_sign )
		rm -rf /tmp/r2ios
		make install DESTDIR=/tmp/r2ios
		( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz * )
		rm -rf sys/cydia/radare2/root
		mkdir -p sys/cydia/radare2/root
		sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C sys/cydia/radare2/root
		( cd sys/cydia/radare2 ; sudo make clean ; sudo make )
	fi
fi
