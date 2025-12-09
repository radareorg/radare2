#!/bin/bash

# Unified SDK script

. sys/sdk-common.sh

WRKDIR=/tmp
SDKDIR=${WRKDIR}/r2-sdk
if [ -n "$1" ]; then
	if [ -f "$1" ]; then
		echo "Target directory exists. Cant build the SDK in there"
		exit 1
	fi
	SDKDIR="$1"
fi

OS=`uname`

if [ "$OS" = "Darwin" ]; then
	# On macOS, build xcframework for iOS and macOS
	echo "Building xcframework for iOS and macOS"
	
	# Build iOS SDK
	echo "Building iOS SDK..."
	INSTALL_DST_IOS="/tmp/r2ios"
	sys/sdk-ios.sh -archs arm64 -d "$INSTALL_DST_IOS"
	
	# Build macOS SDK
	echo "Building macOS SDK..."
	INSTALL_DST_MACOS="/tmp/r2macos"
	sys/sdk-macos.sh -archs x86_64+arm64 -d "$INSTALL_DST_MACOS"
	
	# Create xcframework
	echo "Creating xcframework..."
	XCF_DST="/tmp/Radare2.xcframework"
	rm -rf "$XCF_DST"
	mkdir -p "$XCF_DST"

	# Prepare headers with module maps
	XCF_HEADERS_IOS="/tmp/xcframework_headers/ios"
	XCF_HEADERS_MACOS="/tmp/xcframework_headers/macos"
	rm -rf "$XCF_HEADERS_IOS" "$XCF_HEADERS_MACOS"
	mkdir -p "$XCF_HEADERS_IOS" "$XCF_HEADERS_MACOS"

	# Copy headers
	cp -r "$INSTALL_DST_IOS/usr/local/include/"* "$XCF_HEADERS_IOS/"
	cp -r "$INSTALL_DST_MACOS/usr/local/include/"* "$XCF_HEADERS_MACOS/"

	# Add module.modulemap
	cat > "$XCF_HEADERS_IOS/module.modulemap" <<'EOF'
module Radare2 [extern_c] {
  umbrella "."
  export *
}
EOF
	cat > "$XCF_HEADERS_MACOS/module.modulemap" <<'EOF'
module Radare2 [extern_c] {
  umbrella "."
  export *
}
EOF

	# For iOS
	IOS_LIB="$INSTALL_DST_IOS/usr/local/lib/libr.a"
	IOS_HEADERS="$XCF_HEADERS_IOS"

	# For macOS
	MACOS_LIB="$INSTALL_DST_MACOS/usr/local/lib/libr.a"
	MACOS_HEADERS="$XCF_HEADERS_MACOS"
	
	xcodebuild -create-xcframework \
		-library "$IOS_LIB" \
		-headers "$IOS_HEADERS" \
		-library "$MACOS_LIB" \
		-headers "$MACOS_HEADERS" \
		-output "$XCF_DST"
	
	if [ $? -eq 0 ]; then
		echo "XCFramework created at $XCF_DST"
		# Zip it
		OUTDIR=$PWD
		(
			cd "$(dirname "$XCF_DST")" || exit 1
			zip -r "${OUTDIR}/Radare2.xcframework.zip" "$(basename "$XCF_DST")"
		)
		zip -r Radare2.xcframework.zip "$XCF_DST"
		echo "Zipped to Radare2.xcframework.zip"
	else
		echo "Failed to create xcframework"
		exit 1
	fi
else
	# Generic Unix build
	export CFLAGS="-Os -fPIC"
	make mrproper
	if [ -z "${R2_PLUGINS_CFG}" ]; then
		R2_PLUGINS_CFG=dist/plugins-cfg/plugins.bin.cfg
	fi
	cp -f "${R2_PLUGINS_CFG}" plugins.cfg
	./configure --prefix="$PREFIX" --with-libr --without-gpl || exit 1
	make -j8 || exit 1
	rm -rf "${SDKDIR}"
	mkdir -p "${SDKDIR}"/lib
	rm -f libr/libr.a
	cp -rf libr/include "${SDKDIR}"
	mkdir -p "${SDKDIR}/include/sdb"
	cp -rf subprojects/sdb/include/sdb/* "${SDKDIR}/include/sdb"
	FILES=`find libr shlr -iname '*.a'`
	cp -f ${FILES} "${SDKDIR}"/lib
	AR=`uname -m`
	SF=r2sdk-${OS}-${AR}

	(
	cd "${WRKDIR}"
	mv r2-sdk "${SF}"
	zip -r "${SF}".zip "${SF}"
	)
	mv "${WRKDIR}/${SF}" .
	mv "${WRKDIR}/${SF}".zip .
	ln -fs "${SF}" r2sdk
fi
