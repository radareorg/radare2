#!/bin/bash

# You can modify these variables
PREFIX="/usr"
INSTALL_DST="/tmp/r2ios"
USE_SIMULATOR=0
#SIMULATOR_ARCHS="i386+x86_64"
SIMULATOR_ARCHS="x86_64"
PACKAGE_RADARE=0
EMBED_BITCODE=1
CFLAGS="-O2 -miphoneos-version-min=10.0"
DOSH=0
ARCHS="" # Will be set by -archs argument. If you want to set it -> e.g. ARCHS="armv7+arm64".
MERGE_LIBS=1 # Will merge libs if you build for arm and simulator 

# Environment variables
export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:$PATH
export PATH=`pwd`/sys:${PATH}
export CC=`pwd`/sys/ios-sdk-gcc
export IOSVER=9.0
export IOSINC=`pwd`/sys/ios-include
export USE_IOS_STATIC=0

echo "If xcrun --sdk iphoneos cant find the profile use this line:"
echo " sudo xcode-select -switch /Applications/Xcode.app"

PLUGINS_CFG=plugins.ios-store.cfg
#PLUGINS_CFG=plugins.ios.cfg

if [ "${EMBED_BITCODE}" = 1 ]; then
	export CFLAGS="$CFLAGS -fembed-bitcode"
	export LDFLAGS="$LDFLAGS -fembed-bitcode"
fi

iosConfigure() {
	cp -f ${PLUGINS_CFG} plugins.cfg
	./configure --with-libr --prefix=${PREFIX} --with-ostype=darwin \
		--disable-debugger --without-gpl \
		--without-fork --without-libuv --with-compiler=ios-sdk \
		--target=arm64-unknown-darwin
	return $?
}

iosClean() {
	make clean
	rm -rf libr/.libr libr/.libr2 libr/libr.a libr/libr.dylib shlr/libr_shlr.a
	rm -rf shlr/capstone
}

iosBuild() {
	time make -j4 AR="xcrun --sdk ${SDK} ar" || exit 1
	# Build and sign
	( cd binr/radare2 ; make ios_sdk_sign )
	make install DESTDIR="$INSTALL_DST"
	rm -rf "$INSTALL_DST/$PREFIX"/share/radare2/*/www/*/node_modules
	return $?
}

iosMergeLibs() {
	mkdir -p $INSTALL_DST/$PREFIX/lib_merged
	#echo "Merging dynamic libs"
	#lipo "$INSTALL_DST/$PREFIX"/lib/libr*git.dylib $INSTALL_DST/$PREFIX/lib_simulator/libr*git.dylib -output $INSTALL_DST/$PREFIX/lib_merged/libr2.dylib -create
	echo "Merging static libs (only libr.a)"
	lipo "$INSTALL_DST/$PREFIX"/lib/libr.a "$INSTALL_DST/$PREFIX"/lib_simulator/libr.a -output "$INSTALL_DST/$PREFIX"/lib_merged/libr.a -create
	echo "Merging shared libs (only libr.dylib)"
	lipo "$INSTALL_DST/$PREFIX/lib/libr.dylib" \
		"$INSTALL_DST/$PREFIX"/lib_simulator/libr.dylib \
		-output "$INSTALL_DST/$PREFIX"/lib_merged/libr.dylib -create
	echo "You can find the merged libs in $INSTALL_DST$PREFIX/lib_merged"
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
	echo "The following arguments are available:"

	echo "    -a, --archs"
	echo "        Select the archs, you want to build for."
	echo "        Available archs: armv7, armv7s, arm64, all" 
	echo "        You can select multiple archs by concatenating"
	echo "        them with a '+' sign."
	echo "        Or specify 'all' to build for armv7+armv7s+arm64."
	echo "        See the examples below."

	echo "    -h, --help"
	echo "        Show this text."

	echo "    -p, --package"
	echo "        Package radare2."

	echo "    -s, --shell"
	echo "        Run shell."

	echo "    -f, --full"
	echo "        Same as -archs all -simulator."

	echo "    -simulator"
	echo "        Build also for i386 and x86_64 archs."
	echo "        So you can use radare2 in the iOS simulator."

	echo "Examples:"
	echo "    sys/ios-sdk.sh -archs arm64"
	echo "    sys/ios-sdk.sh -archs armv7s+arm64 -simulator"
	echo "    sys/ios-sdk.sh -archs all -simulator"

	echo "You can also modify some variables in sys/ios-sdk.sh."
}

# Show help text, if no archs are selected
if [ $# -eq 0 ] && [ "${#ARCHS}" = 0 ] && [ "${USE_SIMULATOR}" = 0 ]; then
	echo "You need to specify the archs you want to build for."
	echo "Use the -archs/-simulator argument or modify the ARCHS/USE_SIMULATOR variable in sys/ios-sdk.sh."
	echo
	showHelp
	exit 0
fi

while test $# -gt 0; do
	case "$1" in 
	-full|--full|-f)
		shift
		ARCHS="armv7s+arm64"
		USE_SIMULATOR=1
		;;
	-shell|--shell|-s)
		DOSH=1
		shift
		;;
	-archs|-a|--archs)
		shift
		if test $# -gt 0; then
			if [ "$1" == "all" ]; then
				ARCHS="armv7+armv7s+arm64"
			else
				ARCHS=$1
			fi
		fi
		shift
		;;
	-p|--package)
		iosPackage
		exit 0
		;;
	-simulator)
		USE_SIMULATOR=1
		shift
		;;
	*|-h|--help)
		showHelp
		exit 0
		;;
	esac
done


### BUILD PHASE

# Print which archs we are building for
echo "Will build for \\c"
if [ "${#ARCHS}" -gt 0 ]; then
	echo "$ARCHS \\c"
	[ "${USE_SIMULATOR}" = 1 ] && echo "and \\c"
fi
[ "${USE_SIMULATOR}" = 1 ] && echo "simulator($SIMULATOR_ARCHS)"

if [ "${DOSH}" = 1 ]; then
	echo "Inside ios-sdk shell"
	if [ "${USE_SIMULATOR}" = 1 ]; then
		export CPU="$SIMULATOR_ARCHS"
		export SDK=iphonesimulator
	else
		[ -z "$ARCHS" ] && ARCHS="armv7s+arm64"
		export CPU="$ARCHS"
		export SDK=iphoneos
	fi
CPUS=""
CPU=`echo $CPU | sed -e 's,+, ,g'`
EXTRA=""
for a in `IFS=+ echo ${CPU}` ; do
        CPUS="-arch $a ${CPUS}"
done
export CPUS="${CPUS}"
export LD="xcrun --sdk ${SDK} ld"
export ALFLAGS="${CPUS}"
export LDFLAGS="${LDFLAGS} ${CPUS}"
	export PS1="[ios-sdk-$CPU]> "
	${SHELL}
	echo "Outside ios-sdk shell"
	exit $?
fi
echo
sleep 1

rm -rf "$INSTALL_DST"

# Build radare2 for i386 and x86_64
if [ "${USE_SIMULATOR}" = 1 ]; then
	iosClean
	if [ 1 = 0 ]; then
		iosConfigure
		if [ $? = 0 ]; then
			export CPU="$SIMULATOR_ARCHS"
			export SDK=iphonesimulator
			echo "Building for simulator($SIMULATOR_ARCHS)"
			sleep 1
			iosBuild
		fi
	else
		sys/ios-simulator.sh
	fi
	# backup lib folder of simulator
	if [ "${#ARCHS}" -gt 0 ]; then
		rm -rf "$INSTALL_DST/$PREFIX"/lib_simulator
		mv "$INSTALL_DST/$PREFIX"/lib "$INSTALL_DST/$PREFIX"/lib_simulator
	else
		cp -r "$INSTALL_DST/$PREFIX"/lib "$INSTALL_DST/$PREFIX"/lib_simulator
	fi
fi

# check if arm archs were selected and if so build radare2 for them
# XXX this is a bashism
if [ "${#ARCHS}" -gt 0 ]; then
	iosClean
	iosConfigure
	if [ "$?" = 0 ]; then
		export CPU="$ARCHS"
		export SDK=iphoneos
		echo "Building for $CPU"
		sleep 1
		iosBuild
		if [ "${PACKAGE_RADARE}" = 1 ]; then
			iosPackage
		fi
	fi
fi

# Merge libs if built for simulator and arm archs
if [ "${MERGE_LIBS}" = 1 ]; then
	if [ "${USE_SIMULATOR}" = 1 ] && [ "${#ARCHS}" -gt 0 ]; then
		iosMergeLibs
	fi
fi
