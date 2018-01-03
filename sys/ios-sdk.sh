#!/bin/sh

# You can modify these variables
PREFIX="/usr"
INSTALL_DST="/tmp/r2ios"
USE_SIMULATOR=0
#SIMULATOR_ARCHS="i386+x86_64"
SIMULATOR_ARCHS="x86_64"
PACKAGE_RADARE=0
EMBED_BITCODE=1
CFLAGS="-O2"
ARCHS="" # Will be set by -archs argument. If you want to set it -> e.g. ARCHS="armv7+arm64".
MERGE_LIBS=1 # Will merge libs if you build for arm and simulator 

# Environment variables
export PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:$PATH
export PATH=`pwd`/sys:${PATH}
export CC=`pwd`/sys/ios-sdk-gcc
export LD="xcrun --sdk iphoneos ld"
export IOSVER=9.0
export IOSINC=`pwd`/sys/ios-include
export USE_IOS_STORE=1

if [ "${EMBED_BITCODE}" = 1 ]; then
	export CFLAGS="$CFLAGS -fembed-bitcode"
else 
	export CFLAGS=$CFLAGS
fi

iosConfigure() {
	if [ "${USE_IOS_STORE}" = 1 ]; then
		cp -f plugins.ios-store.cfg plugins.cfg
	else
		cp -f plugins.ios.cfg plugins.cfg
	fi
	./configure --prefix=${PREFIX} --with-ostype=darwin \
	  --without-pic --with-nonpic --without-fork \
	  --with-compiler=ios-sdk --target=arm-unknown-darwin
	return $?
}

iosClean() {
	make clean
}

iosBuild() {
    time make -j4 || exit 1
    # Build and sign
    ( cd binr/radare2 ; make ios_sdk_sign )
    make install DESTDIR=$INSTALL_DST
    rm -rf $INSTALL_DST/$PREFIX/share/radare2/*/www/enyo/node_modules
    return $?
}

iosMergeLibs() {
	mkdir $INSTALL_DST/$PREFIX/lib_merged
	echo "\\nMerging dynamic libs"
	lipo $INSTALL_DST/$PREFIX/lib/libr*git.dylib $INSTALL_DST/$PREFIX/lib_simulator/libr*git.dylib -output $INSTALL_DST/$PREFIX/lib_merged/libr2.dylib -create
	echo "Merging static libs (only libr.a)"
	lipo $INSTALL_DST/$PREFIX/lib/libr.a $INSTALL_DST/$PREFIX/lib_simulator/libr.a -output $INSTALL_DST/$PREFIX/lib_merged/libr.a -create
	echo "\\nYou can find the merged libs in $INSTALL_DST$PREFIX/lib_merged"
}

iosPackage() {
	( cd $INSTALL_DST && tar czvf $INSTALL_DST-${CPU}.tar.gz * )
	# Prepare radare2
	rm -rf sys/cydia/radare2/root
	rm -rf sys/cydia/radare2/root/usr/lib/*.dSYM
	rm -rf sys/cydia/radare2/root/usr/lib/*.a
	mkdir -p sys/cydia/radare2/root
	sudo tar xpzvf $INSTALL_DST-${CPU}.tar.gz -C sys/cydia/radare2/root
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

	echo "\\n\\t-archs"
	echo "\\t\\tSelect the archs, you want to build for."
	echo "\\t\\tAvailable archs: armv7, armv7s, arm64, all" 
	echo "\\t\\tYou can select multiple archs by concatenating"
	echo "\\t\\tthem with a '+' sign."
	echo "\\t\\tOr specify 'all' to build for armv7+armv7s+arm64."
	echo "\\t\\tSee the examples below."

	echo "\\n\\t-h, --help"
	echo "\\t\\tShow this text."

	echo "\\n\\t-p"
	echo "\\t\\tPackage radare2."

	echo "\\n\\t-s"
	echo "\\t\\tRun shell."

	echo "\\n\\t-simulator"
	echo "\\t\\tBuild also for i386 and x86_64 archs."
	echo "\\t\\tSo you can use radare2 in the iOS simulator."

	echo "\\nExamples:"
	echo "\\tsys/ios-sdk.sh -archs arm64"
	echo "\\tsys/ios-sdk.sh -archs armv7+arm64 -simulator"
	echo "\\tsys/ios-sdk.sh -archs all -simulator"

	echo "\\nYou can also modify some variables in sys/ios-sdk.sh."
}

# Show help text, if no archs are selected
if [ $# -eq 0 ] && [ "${#ARCHS}" = 0 ] && [ "${USE_SIMULATOR}" = 0 ]; then
	echo "You need to specify the archs you want to build for."
	echo "Use the -archs/-simulator argument or modify the ARCHS/USE_SIMULATOR variable in sys/ios-sdk.sh.\\n"
	showHelp
	exit 0
fi

while test $# -gt 0; do
	case "$1" in 
		-archs)
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
		-p)	
			iosPackage
 			exit 0
		 	;;
		-s)
			if [ "${USE_SIMULATOR}" = 1 ]; then
				export CPU="$SIMULATOR_ARCHS"
				export SDK=iphonesimulator
			fi
			export PS1="\033[33m[ios-sdk-$CPU \w]> \033[0m"
			exec "$SHELL"
			exit $?
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
echo
sleep 2

rm -rf $INSTALL_DST

# Build radare2 for i386 and x86_64
if [ "${USE_SIMULATOR}" = 1 ]; then
	iosClean
	iosConfigure
	if [ $? = 0 ]; then
		export CPU="$SIMULATOR_ARCHS"
		export SDK=iphonesimulator
		echo "\\nBuilding for simulator($SIMULATOR_ARCHS)\\n"
		sleep 1
		iosBuild
		# backup lib folder of simulator
		cp -r $INSTALL_DST/$PREFIX/lib $INSTALL_DST/$PREFIX/lib_simulator
	fi
fi

# check if arm archs were selected and if so build radare2 for them
if [ "${#ARCHS}" -gt 0 ]; then
	iosClean
	iosConfigure
	if [ "$?" = 0 ] && [ "${#ARCHS}" -gt 0 ]; then
		export CPU=$ARCHS
		export SDK=iphoneos
		echo "\\nBuilding for $CPU\\n"
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
