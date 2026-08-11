#!/bin/bash

# Android SDK builder

set -euo pipefail

CALLER_DIR=$PWD
cd "$(dirname "$0")/.."
ROOT=$PWD
SCRIPT="$ROOT/sys/android-sdk.sh"
PREFIX=/usr/local
DEFAULT_ARCHS="arm+arm64+x86+x86_64"
ARCHS=$DEFAULT_ARCHS
ANDROID_API=${ANDROID_API:-28}
JOBS=${JOBS:-4}
OUTPUT=""
PLUGINS_CFG=${R2_PLUGINS_CFG:-dist/plugins-cfg/plugins.android.cfg}
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
	SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null || date +%s)
fi

showHelp() {
	echo "Android SDK builder"
	echo
	echo "Usage: $0 [options]"
	echo
	echo "Options:"
	echo "    -a, --archs ARCHS    Architectures separated by + or ,"
	echo "                         (arm, arm64, x86, x86_64; default: $DEFAULT_ARCHS)"
	echo "    --api LEVEL          Android API level (default: $ANDROID_API)"
	echo "    -j, --jobs JOBS      Parallel build jobs (default: $JOBS)"
	echo "    -o, --output FILE    Output zip path"
	echo "    -h, --help           Show this help"
	echo
	echo "Examples:"
	echo "    sys/android-sdk.sh"
	echo "    sys/android-sdk.sh -a arm64+x86_64 --api 28"
}

fail() {
	echo "android-sdk: $*" >&2
	exit 1
}

buildAbi() {
	local ndk_arch=$1
	local android_abi=$2
	local target=$3
	local install_dst=$4
	local make=make

	if gmake --help >/dev/null 2>&1; then
		make=gmake
	fi

	export CFLAGS="-fPIC -Oz -DNDEBUG"
	export LDFLAGS=""
	case "$ndk_arch" in
	aarch64|x86_64)
		export LDFLAGS="-Wl,-z,max-page-size=16384"
		;;
	esac
	export AR=llvm-ar
	export RANLIB=llvm-ranlib

	echo "Building Android SDK libraries for $android_abi (API $ANDROID_API)"
	if [ -f libr/config.mk ]; then
		"$make" mrproper
	fi
	cp -f "$PLUGINS_CFG" plugins.cfg
	./configure --with-compiler=android --with-ostype=android \
		--target="$target" --prefix="$PREFIX" --with-libr \
		--with-bundle-prefix --without-gpl --without-sqsh \
		--with-checks-level=0
	"$make" -s -j "$JOBS"
	"$make" -s install DESTDIR="$install_dst"
}

if [ "${1:-}" = "--build-abi" ]; then
	[ $# = 5 ] || fail "invalid internal build arguments"
	buildAbi "$2" "$3" "$4" "$5"
	exit 0
fi

while [ $# -gt 0 ]; do
	case "$1" in
	-a|--archs)
		[ $# -gt 1 ] || fail "$1 requires an argument"
		ARCHS=$2
		shift 2
		;;
	--api)
		[ $# -gt 1 ] || fail "$1 requires an argument"
		ANDROID_API=$2
		shift 2
		;;
	-j|--jobs)
		[ $# -gt 1 ] || fail "$1 requires an argument"
		JOBS=$2
		shift 2
		;;
	-o|--output)
		[ $# -gt 1 ] || fail "$1 requires an argument"
		OUTPUT=$2
		shift 2
		;;
	-h|--help)
		showHelp
		exit 0
		;;
	*)
		fail "unknown option: $1"
		;;
	esac
done

case "$ANDROID_API" in
""|*[!0-9]*)
	fail "invalid Android API level: $ANDROID_API"
	;;
esac
case "$JOBS" in
""|*[!0-9]*)
	fail "invalid job count: $JOBS"
	;;
esac
[ "$JOBS" -gt 0 ] || fail "job count must be greater than zero"
command -v zip >/dev/null 2>&1 || fail "zip is required"

VERSION=$(./configure -qV)
SDK_NAME="radare2-$VERSION-android-sdk"
if [ -z "$OUTPUT" ]; then
	OUTPUT="$CALLER_DIR/$SDK_NAME.zip"
elif [ "${OUTPUT#/}" = "$OUTPUT" ]; then
	OUTPUT="$CALLER_DIR/$OUTPUT"
fi

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/r2-android-sdk.XXXXXX")
SDK_ROOT="$WORKDIR/package/$SDK_NAME"
mkdir -p "$SDK_ROOT/include" "$SDK_ROOT/lib"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT HUP INT TERM

copyLibraries() {
	local source_dir=$1
	local dest_dir=$2
	local source_file
	local dest_file

	mkdir -p "$dest_dir"
	while IFS= read -r source_file; do
		dest_file="$dest_dir/$(basename "$source_file")"
		if [ -f "$dest_file" ] && ! cmp -s "$source_file" "$dest_file"; then
			fail "library name collision: $(basename "$source_file")"
		fi
		cp -Lf "$source_file" "$dest_file"
	done < <(find "$source_dir" \( -type f -o -type l \) \( -name '*.a' -o -name '*.so' \) -print)
}

rewritePkgConfig() {
	local pkg_dir=$1
	local android_abi=$2
	local pc

	[ -d "$pkg_dir" ] || return 0
	for pc in "$pkg_dir"/*.pc; do
		[ -f "$pc" ] || continue
		sed \
			-e 's|^prefix=.*|prefix=${pcfiledir}/../../..|' \
			-e 's|^exec_prefix=.*|exec_prefix=${prefix}|' \
			-e "s|^libdir=.*|libdir=\${prefix}/lib/$android_abi|" \
			-e 's|^includedir=.*|includedir=${prefix}/include|' \
			"$pc" > "$pc.tmp"
		mv -f "$pc.tmp" "$pc"
	done
}

FIRST_ABI=1
BUILT_ABIS=""
NORMALIZED_ARCHS=$(printf '%s' "$ARCHS" | tr ',+' '  ')
export ANDROID_API JOBS PLUGINS_CFG SOURCE_DATE_EPOCH

for arch in $NORMALIZED_ARCHS; do
	case "$arch" in
	arm|armeabi-v7a)
		NDK_ARCH=arm
		ANDROID_ABI=armeabi-v7a
		TARGET=arm-linux-androideabi
		;;
	arm64|aarch64|arm64-v8a)
		NDK_ARCH=aarch64
		ANDROID_ABI=arm64-v8a
		TARGET=aarch64-linux-android
		;;
	x86)
		NDK_ARCH=x86
		ANDROID_ABI=x86
		TARGET=i686-linux-android
		;;
	x64|x86_64)
		NDK_ARCH=x86_64
		ANDROID_ABI=x86_64
		TARGET=x86_64-linux-android
		;;
	*)
		fail "unsupported architecture: $arch"
		;;
	esac

	case " $BUILT_ABIS " in
	*" $ANDROID_ABI "*)
		continue
		;;
	esac
	BUILT_ABIS="$BUILT_ABIS $ANDROID_ABI"
	INSTALL_DST="$WORKDIR/install-$ANDROID_ABI"
	mkdir -p "$INSTALL_DST"
	sys/android-shell.sh "$NDK_ARCH" "$SCRIPT" --build-abi \
		"$NDK_ARCH" "$ANDROID_ABI" "$TARGET" "$INSTALL_DST"
	INSTALL_PREFIX="$INSTALL_DST$PREFIX"
	[ -d "$INSTALL_PREFIX/include/libr" ] || fail "missing headers for $ANDROID_ABI"
	[ -d "$INSTALL_PREFIX/lib" ] || fail "missing libraries for $ANDROID_ABI"

	if [ "$FIRST_ABI" = 1 ]; then
		cp -R "$INSTALL_PREFIX/include/." "$SDK_ROOT/include"
		if [ -d "$INSTALL_PREFIX/share/radare2" ]; then
			mkdir -p "$SDK_ROOT/share"
			cp -R "$INSTALL_PREFIX/share/radare2" "$SDK_ROOT/share/radare2"
		fi
		FIRST_ABI=0
	elif ! diff -qr "$SDK_ROOT/include" "$INSTALL_PREFIX/include" >/dev/null; then
		diff -ru "$SDK_ROOT/include" "$INSTALL_PREFIX/include" || true
		fail "installed headers differ for $ANDROID_ABI"
	fi

	ABI_LIBDIR="$SDK_ROOT/lib/$ANDROID_ABI"
	copyLibraries "$INSTALL_PREFIX/lib" "$ABI_LIBDIR"
	if [ -d "$INSTALL_PREFIX/lib/pkgconfig" ]; then
		mkdir -p "$ABI_LIBDIR/pkgconfig"
		cp -R "$INSTALL_PREFIX/lib/pkgconfig/." "$ABI_LIBDIR/pkgconfig"
		rewritePkgConfig "$ABI_LIBDIR/pkgconfig" "$ANDROID_ABI"
	fi
	find "$ABI_LIBDIR" -maxdepth 1 -name '*.a' -print -quit | grep -q . || \
		fail "no static libraries found for $ANDROID_ABI"
	find "$ABI_LIBDIR" -maxdepth 1 -name '*.so' -print -quit | grep -q . || \
		fail "no shared libraries found for $ANDROID_ABI"
done

[ "$FIRST_ABI" = 0 ] || fail "no architectures selected"
cp -f COPYING.md "$SDK_ROOT"
printf '%s\n' \
	"radare2 Android SDK $VERSION" \
	"" \
	"Android API level: $ANDROID_API" \
	"ABIs:$BUILT_ABIS" \
	"" \
	"Layout:" \
	"  include/libr/              Public radare2 headers" \
	"  lib/<android-abi>/         Static and shared libraries" \
	"  lib/<android-abi>/pkgconfig/  Relocatable pkg-config files" \
	"  share/                     Runtime data files" \
	"" \
	"Use include/libr as an include directory and lib/\${ANDROID_ABI} as" \
	"a library directory. Set PKG_CONFIG_PATH to the matching pkgconfig" \
	"directory when using pkg-config." > "$SDK_ROOT/README.txt"
printf 'version=%s\napi=%s\nabis=%s\n' \
	"$VERSION" "$ANDROID_API" "${BUILT_ABIS# }" > "$SDK_ROOT/METADATA"

mkdir -p "$(dirname "$OUTPUT")"
ZIP_PATH="$WORKDIR/$SDK_NAME.zip"
(
	cd "$WORKDIR/package"
	zip -qry "$ZIP_PATH" "$SDK_NAME"
)
if command -v unzip >/dev/null 2>&1; then
	unzip -tq "$ZIP_PATH" >/dev/null
fi
mv -f "$ZIP_PATH" "$OUTPUT"
echo "$OUTPUT"
