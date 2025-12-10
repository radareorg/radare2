#!/bin/bash

# Common functions for SDK building

# Default variables
PREFIX="/usr/local"
INSTALL_DST="/tmp/r2sdk"
CFLAGS="-O2"
DOSH=0
ARCHS=""
MERGE_LIBS=1

sdkClean() {
	make clean || true
	rm -rf libr/.libr libr/.libr2 libr/libr.a libr/libr.dylib shlr/libr_shlr.a
	rm -rf shlr/.libr/
	rm -rf shlr/capstone
	rm -rf subprojects/sdb/src/libsdb.a
	rm -rf subprojects/capstone-v5/libcapstone.a
}

sdkBuild() {
	time make -j4 || exit 1
	make install DESTDIR="$INSTALL_DST"
	rm -rf "$INSTALL_DST/$PREFIX"/share/radare2/*/www/*/node_modules
	return $?
}

sdkMergeLibs() {
	mkdir -p "$INSTALL_DST/$PREFIX/lib_merged"
	echo "Merging static libs (libr.a)"
	local libs=""
	for arch in $(echo $ARCHS | tr '+' ' '); do
		if [ -f "$INSTALL_DST/$PREFIX/lib_$arch/libr.a" ]; then
			libs="$libs $INSTALL_DST/$PREFIX/lib_$arch/libr.a"
		fi
	done
	if [ -f "$INSTALL_DST/$PREFIX/lib/libr.a" ]; then
		libs="$libs $INSTALL_DST/$PREFIX/lib/libr.a"
	fi
	if [ -n "$libs" ]; then
		lipo $libs -output "$INSTALL_DST/$PREFIX/lib_merged/libr.a" -create
	fi
	echo "Merging shared libs (libr.dylib)"
	libs=""
	for arch in $(echo $ARCHS | tr '+' ' '); do
		if [ -f "$INSTALL_DST/$PREFIX/lib_$arch/libr.dylib" ]; then
			libs="$libs $INSTALL_DST/$PREFIX/lib_$arch/libr.dylib"
		fi
	done
	if [ -f "$INSTALL_DST/$PREFIX/lib/libr.dylib" ]; then
		libs="$libs $INSTALL_DST/$PREFIX/lib/libr.dylib"
	fi
	if [ -n "$libs" ]; then
		lipo $libs -output "$INSTALL_DST/$PREFIX/lib_merged/libr.dylib" -create
	fi
	echo "Merged libs in $INSTALL_DST$PREFIX/lib_merged"
}

showHelp() {
	echo "Usage: $0 [options]"
	echo
	echo "Options:"
	echo "    -a, --archs ARCHS    Architectures to build (e.g., arm64, x86_64+arm64)"
	echo "    -h, --help           Show this help"
	echo "    -s, --shell          Run shell with environment set"
	echo "    -p, --prefix PREFIX  Installation prefix (default: $PREFIX)"
	echo "    -d, --dest DEST      Installation destination (default: $INSTALL_DST)"
}

parseArgs() {
	while test $# -gt 0; do
		case "$1" in
		-shell|--shell|-s)
			DOSH=1
			shift
			;;
		-archs|-a|--archs)
			shift
			if test $# -gt 0; then
				ARCHS=$1
			fi
			shift
			;;
		-prefix|-p|--prefix)
			shift
			if test $# -gt 0; then
				PREFIX=$1
			fi
			shift
			;;
		-dest|-d|--dest)
			shift
			if test $# -gt 0; then
				INSTALL_DST=$1
			fi
			shift
			;;
		-h|--help)
			showHelp
			exit 0
			;;
		*)
			shift
			;;
		esac
	done
}

setupShell() {
	local platform=$1
	echo "Inside $platform-sdk shell"
	export CPU="$ARCHS"
	local CPUS=""
	for a in $(echo $ARCHS | tr '+' ' '); do
		CPUS="-arch $a ${CPUS}"
	done
	export CPUS="${CPUS}"
	export LDFLAGS="${LDFLAGS} ${CPUS}"
	export PS1="[$platform-sdk-$CPU]> "
	${SHELL}
	echo "Outside $platform-sdk shell"
	exit $?
}
