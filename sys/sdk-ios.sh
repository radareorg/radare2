#!/bin/bash

# iOS SDK builder

. sys/sdk-common.sh

# iOS specific variables
USE_SIMULATOR=0
SIMULATOR_ARCHS="arm64"
PACKAGE_RADARE=0
EMBED_BITCODE=0
PLUGINS_CFG=plugins.ios-store.cfg

# Environment variables
. sys/ios-env.sh
export USE_IOS_STATIC=0

set -eo pipefail

echo "If xcrun --sdk iphoneos cant find the profile use this line:"
echo " sudo xcode-select -switch /Applications/Xcode.app"

if [ "${EMBED_BITCODE}" = 1 ]; then
	export CFLAGS="$CFLAGS -fembed-bitcode"
	export LDFLAGS="$LDFLAGS -fembed-bitcode"
fi

iosConfigure() {
	cp -f dist/plugins-cfg/${PLUGINS_CFG} plugins.cfg
	./configure --with-libr --prefix=${PREFIX} --with-ostype=darwin \
		--with-bundle-prefix --disable-debugger --without-gpl \
		--without-fork --with-compiler=ios-sdk-clang \
		--target=arm64-unknown-darwin
	return $?
}

iosPackage() {
	( cd "$INSTALL_DST" && tar czvf $INSTALL_DST-${CPU}.tar.gz * )
	# Prepare radare2
	rm -rf sys/cydia/radare2/root
	rm -rf sys/cydia/radare2/root/usr/lib/*.dSYM
	rm -rf sys/cydia/radare2/root/usr/lib/*.a
	mkdir -p sys/cydia/radare2/root
	sudo tar xpzvf "$INSTALL_DST"-${CPU}.tar.gz -C sys/cydia/radare2/root
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
	return $?
}

showHelp() {
	echo "iOS SDK builder"
	echo
	echo "Options:"
	echo "    -a, --archs ARCHS    Architectures (armv7, armv7s, arm64, all)"
	echo "    -simulator           Build for simulator"
	echo "    -f, --full           Build all archs + simulator"
	echo "    -p, --package        Package radare2"
	echo "    -s, --shell          Run shell"
	echo "    -h, --help           Show help"
	echo
	echo "Examples:"
	echo "    sys/sdk-ios.sh -archs arm64"
	echo "    sys/sdk-ios.sh -archs armv7s+arm64 -simulator"
	echo "    sys/sdk-ios.sh -archs all -simulator"
}

parseArgs "$@"

# iOS specific args
while test $# -gt 0; do
	case "$1" in
	-full|--full|-f)
		shift
		ARCHS="armv7s+arm64"
		USE_SIMULATOR=1
		;;
	-p|--package)
		iosPackage
		exit 0
		;;
	-simulator)
		USE_SIMULATOR=1
		shift
		;;
	*)
		shift
		;;
	esac
done

# Show help if no archs
if [ $# -eq 0 ] && [ "${#ARCHS}" = 0 ] && [ "${USE_SIMULATOR}" = 0 ]; then
	echo "You need to specify the archs you want to build for."
	echo "Use -archs/-simulator or modify ARCHS/USE_SIMULATOR."
	echo
	showHelp
	exit 0
fi


# Build phase
if [ -n "$ARCHS" ] || [ "${USE_SIMULATOR}" = 1 ]; then
    printf "Will build for "
    if [ -n "$ARCHS" ]; then
        printf "%s " "$ARCHS"
        [ "${USE_SIMULATOR}" = 1 ] && printf "and "
    fi
    if [ "${USE_SIMULATOR}" = 1 ]; then
        printf "simulator(%s)" "$SIMULATOR_ARCHS"
    fi
    printf "\n"
else
    echo "Will build for default settings"
fi

if [ "${DOSH}" = 1 ]; then
	setupShell "ios"
fi

echo
sleep 1
rm -rf "$INSTALL_DST"

# Build for simulator
if [ "${USE_SIMULATOR}" = 1 ]; then
	sdkClean
	export CPU="$SIMULATOR_ARCHS"
	export SDK=iphonesimulator
	iosConfigure
	echo "Building for simulator($SIMULATOR_ARCHS)"
	sleep 1
	sdkBuild
	# backup include and lib directories
	if [ "${#ARCHS}" -gt 0 ]; then
		for d in include lib; do
			rm -rf "$INSTALL_DST/$PREFIX"/${d}_simulator
			mv "$INSTALL_DST/$PREFIX"/${d} "$INSTALL_DST/$PREFIX"/${d}_simulator
		done
	else
		for d in include lib; do
			cp -r "$INSTALL_DST/$PREFIX"/${d} "$INSTALL_DST/$PREFIX"/${d}_simulator
		done
	fi
fi

# Build for device
if [ "${#ARCHS}" -gt 0 ]; then
	sdkClean
	export CPU="$ARCHS"
	export SDK=iphoneos
	iosConfigure
	echo "Building for $CPU"
	sleep 1
	sdkBuild
	if [ "${PACKAGE_RADARE}" = 1 ]; then
		iosPackage
	fi
fi

# Merge libs
if [ "${MERGE_LIBS}" = 1 ] && [ "${USE_SIMULATOR}" = 1 ] && [ "${#ARCHS}" -gt 0 ]; then
	sdkMergeLibs
fi
