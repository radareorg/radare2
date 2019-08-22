#!/bin/sh

STOW=0
fromscratch=1 # 1
onlydebug=0
onlymakedeb=0
static=1

if [ -z "${CPU}" ]; then
	export CPU=arm64
	#export CPU=armv7
fi
if [ -z "${PACKAGE}" ]; then
	PACKAGE=radare2
fi

export BUILD=1

if [ ! -d sys/ios-include/mach/vm_behavior.h  ]; then
(
	cd sys && \
	wget http://lolcathost.org/b/ios-include.tar.gz && \
	tar xzvf ios-include.tar.gz
)
fi

. sys/ios-env.sh
if [ "${STOW}" = 1 ]; then
PREFIX=/private/var/radare2
else
PREFIX=/usr
fi

makeDeb() {
	make -C binr ios-sdk-sign
	rm -rf /tmp/r2ios
	make install DESTDIR=/tmp/r2ios
	rm -rf /tmp/r2ios/${PREFIX}/share/radare2/*/www/enyo/node_modules
	( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz ./* )
	rm -rf sys/cydia/radare2/root
	mkdir -p sys/cydia/radare2/root
	sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C sys/cydia/radare2/root
	rm -f sys/cydia/radare2/root/${PREFIX}/lib/*.dSYM
	rm -f sys/cydia/radare2/root/${PREFIX}/lib/*.a
	rm -f sys/cydia/radare2/root/${PREFIX}/lib/*.dylib
	if [ "$static" = 1 ]; then
	(
		rm -f sys/cydia/radare2/root/${PREFIX}/bin/*
		cp -f binr/blob/radare2 sys/cydia/radare2/root/${PREFIX}/bin
		cd sys/cydia/radare2/root/${PREFIX}/bin
		for a in r2 rabin2 rarun2 rasm2 ragg2 rahash2 rax2 rafind2 radiff2 ; do ln -fs radare2 $a ; done
	)
		echo "Signing radare2"
		ldid2 -Sbinr/radare2/radare2_ios.xml sys/cydia/radare2/root/usr/bin/radare2
	else
		for a in sys/cydia/radare2/root/usr/bin/* sys/cydia/radare2/root/usr/lib/*.dylib ; do
			echo "Signing $a"
			ldid2 -Sbinr/radare2/radare2_ios.xml $a
		done
	fi
if [ "${STOW}" = 1 ]; then
	(
		cd sys/cydia/radare2/root/
		mkdir -p usr/bin
		# stow
		echo "Stowing ${PREFIX} into /usr..."
		for a in `cd ./${PREFIX}; ls` ; do
			if [ -d "./${PREFIX}/$a" ]; then
				mkdir -p "usr/$a"
				for b in `cd ./${PREFIX}/$a; ls` ; do
					echo ln -fs "${PREFIX}/$a/$b" usr/$a/$b
					ln -fs "${PREFIX}/$a/$b" usr/$a/$b
				done
			fi
		done
	)
else
	echo "No need to stow anything"
fi
	( cd sys/cydia/radare2 ; sudo make clean ; sudo make PACKAGE=${PACKAGE} )
}

if [ "$1" = makedeb ]; then
	onlymakedeb=1
fi

if [ $onlymakedeb = 1 ]; then
	makeDeb
else
	if [ $fromscratch = 1 ]; then
		if [ $onlydebug = 1 ]; then
			(cd libr/debug ; make clean)
			RV=0
		else
			make clean
			cp plugins.ios.cfg plugins.cfg
			if [ "$static" = 1 ]; then
				./configure --prefix="${PREFIX}" --with-ostype=darwin --without-libuv \
				--with-compiler=ios-sdk --target=arm-unknown-darwin --with-libr
			else
				./configure --prefix="${PREFIX}" --with-ostype=darwin --without-libuv \
				--with-compiler=ios-sdk --target=arm-unknown-darwin
			fi
			RV=$?
		fi
	else
		RV=0
	fi
	if [ $RV = 0 ]; then
		time make -j4
		if [ "$static" = 1 ]; then
			rm -f libr/*/*.dylib
			(
			cd binr ; make clean ; 
			cd blob ; make USE_LTO=1
			xcrun --sdk iphoneos strip radare2
			)
		fi
		if [ $? = 0 ]; then
			makeDeb
		fi
	fi
fi
