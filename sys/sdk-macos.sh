#!/bin/bash

# macOS SDK builder

. sys/sdk-common.sh

: "${R2_MACOS_MIN:=10.10}"

# macOS specific
PLUGINS_CFG=plugins.ios-store.cfg

macosConfigure() {
	: "${MACOSX_DEPLOYMENT_TARGET:=${R2_MACOS_MIN}}"
	export MACOSX_DEPLOYMENT_TARGET

	export CFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET} ${CFLAGS}"
	export LDFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET} ${LDFLAGS}"

	cp -f dist/plugins-cfg/${PLUGINS_CFG} plugins.cfg
	./configure --with-libr --prefix=${PREFIX} --with-ostype=darwin \
		--disable-debugger --without-gpl \
		--without-fork --with-compiler=clang \
		--target=x86_64-apple-darwin
	return $?
}

showHelp() {
	echo "macOS SDK builder"
	echo
	echo "Options:"
	echo "    -a, --archs ARCHS    Architectures (x86_64, arm64, all)"
	echo "    -s, --shell          Run shell"
	echo "    -h, --help           Show help"
	echo
	echo "Examples:"
	echo "    sys/sdk-macos.sh -archs arm64"
	echo "    sys/sdk-macos.sh -archs x86_64+arm64"
	echo "    sys/sdk-macos.sh -archs all"
}

parseArgs "$@"

# Show help if no archs
if [ $# -eq 0 ] && [ "${#ARCHS}" = 0 ]; then
	echo "You need to specify the archs you want to build for."
	echo "Use -archs or modify ARCHS."
	echo
	showHelp
	exit 0
fi

# Build phase
if [ -n "$ARCHS" ]; then
    printf "Will build for %s\n" "$ARCHS"
else
    echo "Will build for default settings"
fi

if [ "${DOSH}" = 1 ]; then
	setupShell "macos"
fi

echo
sleep 1
rm -rf "$INSTALL_DST"

if [ "${#ARCHS}" -gt 0 ]; then
	sdkClean
	macosConfigure
	if [ $? -eq 0 ]; then
		export CPU="$ARCHS"
		echo "Building for $CPU"
		sleep 1
		sdkBuild
	fi
fi
