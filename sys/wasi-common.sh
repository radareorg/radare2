#!/bin/sh
# Common functions for WASI build scripts

wasi_refresh_paths() {
	if [ -d "${WASI_ROOT}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}" ]; then
		export WASI_SDK="${WASI_ROOT}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}"
	elif [ -d "${WASI_ROOT}/wasi-sdk-${WASI_VERSION}" ]; then
		export WASI_SDK="${WASI_ROOT}/wasi-sdk-${WASI_VERSION}"
	fi
	export WASI_SYSROOT="${WASI_SYSROOT:-${WASI_ROOT}/wasi-sysroot-${WASI_VERSION}}"
}

wasi_download() {
	URL="$1"
	OUTPUT="$2"

	if [ -s "$OUTPUT" ]; then
		echo "Using cached `basename "$OUTPUT"`"
		return 0
	fi
	mkdir -p "`dirname "$OUTPUT"`"
	echo "Downloading `basename "$OUTPUT"`..."
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 --retry-delay 2 -o "$OUTPUT" "$URL" || return 1
	elif command -v wget >/dev/null 2>&1; then
		wget -nv -O "$OUTPUT" "$URL" || return 1
	else
		echo "ERROR: neither curl nor wget is available"
		return 1
	fi
	return 0
}

# Setup WASI SDK by downloading if necessary
wasi_setup_sdk() {
	wasi_refresh_paths

	if [ -d "$WASI_SDK" ] && [ -d "$WASI_SYSROOT" ]; then
		echo "Using WASI_SDK=$WASI_SDK"
		echo "Using WASI_SYSROOT=$WASI_SYSROOT"
		return 0
	fi

	echo "Preparing WASI SDK under $WASI_ROOT"
	mkdir -p "$WASI_ROOT" "$WASI_DOWNLOAD_DIR"

	if [ ! -d "$WASI_SDK" ]; then
		wasi_download "$WASI_SDK_URL" "$WASI_SDK_ARCHIVE" || exit 1
		echo "Extracting `basename "$WASI_SDK_ARCHIVE"`..."
		tar xzf "$WASI_SDK_ARCHIVE" -C "$WASI_ROOT" || exit 1
		wasi_refresh_paths
	fi

	if [ ! -d "$WASI_SYSROOT" ]; then
		wasi_download "$WASI_SYSROOT_URL" "$WASI_SYSROOT_ARCHIVE" || exit 1
		echo "Extracting `basename "$WASI_SYSROOT_ARCHIVE"`..."
		tar xzf "$WASI_SYSROOT_ARCHIVE" -C "$WASI_ROOT" || exit 1
		if [ -d "${WASI_ROOT}/wasi-sysroot" ] && [ ! -d "$WASI_SYSROOT" ]; then
			mv "${WASI_ROOT}/wasi-sysroot" "$WASI_SYSROOT" || exit 1
		fi
	fi

	# Verify SDK is now available
	if [ ! -d "$WASI_SDK" ]; then
		echo "ERROR: WASI_SDK directory not found at $WASI_SDK"
		exit 1
	fi

	echo "Using WASI_SDK=$WASI_SDK"
	echo "Using WASI_SYSROOT=$WASI_SYSROOT"
}

# Setup plugins configuration
wasi_setup_plugins() {
	cp -f dist/plugins-cfg/plugins.wasi.cfg plugins.cfg
}

# Build tools for WASI
wasi_build_tools() {
	TOOLS="$1"
	OUTPUT_DIR="$2"

	ERR=0
	mkdir -p "$OUTPUT_DIR"

	for a in ${TOOLS} ; do
		if [ ! -f "binr/$a/$a.wasm" ]; then
			echo "Building $a..."
			make -C "binr/$a" -s || ERR=1
		fi
		cp -f binr/$a/$a.wasm "$OUTPUT_DIR" || ERR=1
	done

	return $ERR
}
