#!/bin/sh

DEFCPU=armv7
BUILD=1
PREFIX="/usr"
# PREFIX=/var/mobile

#if [ ! -d sys/ios-include ]; then
#(
#  cd sys && \
#  curl -o ios-include.tar.gz http://lolcathost.org/b/ios-include.tar.gz && \
#  tar xzvf ios-include.tar.gz
#)
#fi
case "$1" in
''|arm|armv7)
	CPU=armv7
	shift
	;;
arm64|aarch64)
	CPU=arm64
	shift
	;;
-s)
	CPU=armv7
	;;
*)
	echo "Valid values for CPU are: armv7 or arm64 (add -s to start a shell)"
	echo "Run 'sys/rebuild.sh iosdbg' for quick rebuilds for the debugger"
	exit 1
esac
[ -z "$CPU" ] && CPU="$DEFCPU"

export CPU="$CPU"
export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:$PATH
export PATH=`pwd`/sys:${PATH}
export CC=`pwd`/sys/ios-sdk-gcc
export RANLIB="xcrun --sdk iphoneos ranlib"
export LD="xcrun --sdk iphoneos ld"
# set only for arm64, otherwise it is armv7
# select ios sdk version
export IOSVER=8.3
export IOSINC=`pwd`/sys/ios-include
export CFLAGS=-O2
export USE_SIMULATOR=0

if [ "$1" = -s ]; then
	export PS1="\033[33m[ios-sdk-$CPU \w]> \033[0m"
	exec $SHELL
fi

echo
echo "BUILDING R2 FOR iOS CPU = $CPU"
echo
sleep 1

if false ; then
	make clean
	cp -f plugins.tiny.cfg plugins.cfg
	./configure --prefix=${PREFIX} --with-ostype=darwin \
	  --without-pic --with-nonpic \
	  --with-compiler=ios-sdk --target=arm-unknown-darwin
	# --disable-debugger --with-compiler=ios-sdk
fi

if [ $? = 0 ]; then
	time make -j4 || exit 1
	# Build and sign
	( cd binr/radare2 ; make ios_sdk_sign )
	rm -rf /tmp/r2ios
	make install DESTDIR=/tmp/r2ios
	rm -rf /tmp/r2ios/usr/share/radare2/*/www/enyo/node_modules
	( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz * )
	# Prepare radare2
	rm -rf sys/cydia/radare2/root
	rm -rf sys/cydia/radare2/root/usr/lib/*.dSYM
	rm -rf sys/cydia/radare2/root/usr/lib/*.a
	mkdir -p sys/cydia/radare2/root
	sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C sys/cydia/radare2/root
	rm -rf sys/cydia/radare2-dev/root
	# Prepare radare2-dev
	mkdir -p sys/cydia/radare2-dev/root
	mkdir -p sys/cydia/radare2-dev/root/usr/include
	mv sys/cydia/radare2/root/usr/include/* sys/cydia/radare2-dev/root/usr/include
	mkdir -p sys/cydia/radare2-dev/root/usr/lib
	mv sys/cydia/radare2/root/usr/lib/lib* sys/cydia/radare2-dev/root/usr/lib
	mv sys/cydia/radare2/root/usr/lib/pkgconfig sys/cydia/radare2-dev/root/usr/lib
	(
		cd sys/cydia/radare2/root/usr/bin ;
		for a in * ; do strip $a ; done
	)
	( cd sys/cydia/radare2 ; sudo make clean ; sudo make )
	( cd sys/cydia/radare2-dev ; sudo make clean ; sudo make )
fi
