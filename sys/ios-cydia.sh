#!/bin/sh

set -ex
STOW=0
fromscratch=1 # 1
onlymakedeb=0
static=1

if gcc -v 2> /dev/null; then
	export HOST_CC=gcc
fi
if [ -z "${CPU}" ]; then
	export CPU=arm64
	#export CPU=armv7
fi
if [ -z "${PACKAGE}" ]; then
	PACKAGE=radare2
fi

export BUILD=1

. sys/ios-env.sh
if [ "${STOW}" = 1 ]; then
PREFIX=/private/var/radare2
else
PREFIX=/usr
fi

if [ "${ROOTLESS}" = 1 ]; then
	PREFIX=/var/jb/usr
fi

ROOT=dist/cydia/radare2/root

makeDeb() {
	LDID=$(command -v ldid2 || command -v ldid)
	rm -rf /tmp/r2ios
	make install DESTDIR=/tmp/r2ios
	rm -rf /tmp/r2ios/${PREFIX}/share/radare2/*/www/*/node_modules
	( cd /tmp/r2ios && tar czvf ../r2ios-${CPU}.tar.gz ./* )
	rm -rf "${ROOT}"
	mkdir -p "${ROOT}"
	sudo tar xpzvf /tmp/r2ios-${CPU}.tar.gz -C "${ROOT}"
	rm -f "${ROOT}${PREFIX}/lib/"*.a "${ROOT}${PREFIX}/lib/"*.dylib
	rm -rf "${ROOT}${PREFIX}/lib/"*.dSYM
	if [ "$static" = 1 ]; then
	(
		rm -f ${ROOT}/${PREFIX}/bin/*
		cp -f binr/blob/radare2 "${ROOT}/${PREFIX}/bin"
		cd ${ROOT}/${PREFIX}/bin
		for a in r2 rabin2 rarun2 rasm2 ragg2 rahash2 rax2 rafind2 radiff2 ; do ln -fs radare2 $a ; done
	)
		echo "Signing radare2"
		"${LDID}" -Sbinr/radare2/radare2_ios.xml "${ROOT}${PREFIX}/bin/radare2"
	else
		for a in "${ROOT}${PREFIX}/bin/"* "${ROOT}${PREFIX}/lib/"*.dylib ; do
			echo "Signing $a"
			"${LDID}" -Sbinr/radare2/radare2_ios.xml "$a"
		done
	fi
	if [ "${STOW}" = 1 ]; then
		(
		cd "${ROOT}/"
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
	( cd dist/cydia/radare2 ; sudo make clean ; sudo make PACKAGE=${PACKAGE} )
}

if [ "$1" = makedeb ]; then
	onlymakedeb=1
fi

if [ "$1" = "--shell" ]; then
	echo "Entering the ios-cydia shell"
	${SHELL}
	exit 0
fi

if [ $onlymakedeb = 1 ]; then
	makeDeb
else
	export CC="ios-sdk-clang"
	if [ $fromscratch = 1 ]; then
		if [ -f config-user.mk ]; then
			make clean
		fi
		cp -f dist/plugins-cfg/plugins.ios.cfg plugins.cfg
		if [ "$static" = 1 ]; then
			./configure --prefix="${PREFIX}" --with-ostype=darwin \
			--with-compiler=ios-sdk-clang --target=arm-unknown-darwin --with-libr
		else
			./configure --prefix="${PREFIX}" --with-ostype=darwin \
			--with-compiler=ios-sdk-clang --target=arm-unknown-darwin
		fi
	fi
	time make -j4
	if [ "$static" = 1 ]; then
		ls -l libr/util/libr_util.a
		ls -l libr/flag/libr_flag.a
		rm -f libr/*/*.dylib
		(
		cd binr/blob ; make USE_LTO=1
		xcrun --sdk iphoneos strip radare2
		)
	fi
	makeDeb
fi
