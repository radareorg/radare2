#!/bin/sh

if [ -z "${CPU}" ]; then
export CPU=arm64
export CPU=armv7
fi

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

. sys/ios-env.sh

makeDeb() {
	make -C binr ios-sdk-sign
	rm -rf /tmp/r2ios
	make install DESTDIR=/tmp/r2ios
	rm -rf /tmp/r2ios/usr/share/radare2/*/www/enyo/node_modules
	( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz ./* )
	rm -rf sys/cydia/radare2/root
	mkdir -p sys/cydia/radare2/root
	sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C sys/cydia/radare2/root
	( cd sys/cydia/radare2 ; sudo make clean ; sudo make )
}

fromscratch=1
onlymakedeb=0

if [ "$1" = makedeb ]; then
	onlymakedeb=1
fi

if [ $onlymakedeb = 1 ]; then
	makeDeb
else
	if [ $fromscratch = 1 ]; then
		make clean
		./configure --prefix=${PREFIX} --with-ostype=darwin \
			--with-compiler=ios-sdk --target=arm-unknown-darwin
		RV=$?
	else
		RV=0
	fi
	if [ $RV = 0 ]; then
		time make -j2
		if [ $? = 0 ]; then
			makeDeb
		fi
	fi
fi


