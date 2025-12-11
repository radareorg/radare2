#!/bin/sh
# Common functions for WASI build scripts

# Setup WASI SDK by downloading if necessary
wasi_setup_sdk() {
	ARCH=x86_64

	if [ ! -d "$WASI_SDK" ]; then
		echo "WASI SDK not found at $WASI_SDK, downloading..."

		# Determine OS for download URL
		OS=`uname`
		case "$OS" in
		linux|Linux) OS=linux ;;
		darwin|Darwin) OS=macos ;;
		windows|Windows) OS=mingw ;;
		esac
		OS="$ARCH-$OS"

		mkdir -p ~/Downloads/wasi
		rm -f ~/Downloads/wasi/wasi-sdk.tar.gz
		echo "Downloading wasi-sdk-${WASI_VERSION}-$OS.tar.gz..."
		wget -c -O ~/Downloads/wasi/wasi-sdk.tar.gz https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_MAJOR}/wasi-sdk-${WASI_VERSION}-$OS.tar.gz || exit 1

		rm -f ~/Downloads/wasi/wasi-sysroot.tar.gz
		echo "Downloading wasi-sysroot-${WASI_VERSION}.tar.gz..."
		wget -c -O ~/Downloads/wasi/wasi-root.tar.gz https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_MAJOR}/wasi-sysroot-${WASI_VERSION}.tar.gz || exit 1

		echo "Extracting WASI SDK..."
		(
			cd ~/Downloads/wasi
			tar xzvf wasi-sdk.tar.gz
			tar xzvf wasi-root.tar.gz
			mv wasi-sysroot wasi-sysroot-${WASI_VERSION}
		)

		echo "WASI SDK installed successfully"
	fi

	# Verify SDK is now available
	if [ ! -d "$WASI_SDK" ]; then
		echo "ERROR: WASI_SDK directory not found at $WASI_SDK"
		exit 1
	fi

	echo "Using WASI_SDK=$WASI_SDK"
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
		echo "Building $a..."
		make -C binr/$a || ERR=1
		cp -f binr/$a/$a.wasm "$OUTPUT_DIR" || ERR=1
	done

	return $ERR
}
