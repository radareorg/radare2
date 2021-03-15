#!/bin/sh

if [ -z "${CPU}" ]; then
	export CPU=arm64+armv7
	export CPU=arm64
	export CPU=armv7
fi

export CPU=arm64+armv7
export CPU=arm64+armv7
export PLGCFG=plugins.tiny.cfg

export CPU=x86_64
export SDK=iphonesimulator

#export CPU=arm64
export CPU=x86_64
export SDK=appletvsimulator

export CPU=x86_64
export SDK=watchsimulator

export CPU=armv7k
export SDK=watchos

export CPU=i386
export SDK=watchsimulator

export CPU=arm64
export SDK=appletvos

export CPU=armv7k
export SDK=watchos


##########################################

export CPU=x86_64
export SDK=iphonesimulator
export PLGCFG=plugins.ios-store.cfg

export BUILD=1
PREFIX="/usr"
# PREFIX=/var/mobile

if [ ! -d sys/ios-include ]; then
(
	cd sys && \
	wget -c https://lolcathost.org/b/ios-include.tar.gz && \
	tar xzvf ios-include.tar.gz
)
fi

export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:$PATH
export PATH=$(pwd)/sys:${PATH}
export CC="$(pwd)/sys/ios-sdk-gcc"
# set only for arm64, otherwise it is armv7
# select ios sdk version
export IOSVER=10.2
export IOSINC=/
#$(pwd)/sys/ios-include
export CFLAGS="${CFLAGS} -O2"
export USE_SIMULATOR=1
export RANLIB="xcrun --sdk iphoneos ranlib"

if [ "$1" = "-s" ]; then
sh
	exit $?
fi

if true; then
make mrproper
cp -f ${PLGCFG} plugins.cfg
./configure --prefix=${PREFIX} --with-ostype=darwin --with-libr \
	--without-fork --without-libuv --disable-debugger --with-compiler=ios-sdk \
	--target=arm-unknown-darwin || exit 1
fi

if [ $? = 0 ]; then
	time make -j4 || exit 1
	( cd libr ; make libr.dylib )
	if [ $? = 0 ]; then
		( cd binr/radare2 ; make ios_sdk_sign )
		rm -rf /tmp/r2ios
		make install DESTDIR=/tmp/r2ios
		rm -rf /tmp/r2ios/usr/share/radare2/*/www/*/node_modules
		( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz ./* )
		rm -rf sys/cydia/radare2/root
		mkdir -p sys/cydia/radare2/root
		sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C sys/cydia/radare2/root
		( cd sys/cydia/radare2 ; sudo make clean ; sudo make )
	fi
fi
