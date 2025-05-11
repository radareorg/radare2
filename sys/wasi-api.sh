#!/bin/sh

. `dirname $0`/wasi-env.sh

echo "WASI_SDK=$WASI_SDK"

TOOLS="radare2"

if [ ! -d "$WASI_SDK" ]; then
	#OS=linux,macos,mingw
	OS=`uname`
	case "$OS" in
	linux|Linux) OS=linux ; ;;
	darwin|Darwin) OS=macos ; ;;
	windows|Windows) OS=mingw ; ;;
	esac
	mkdir -p ~/Downloads/wasi
	rm -f ~/Downloads/wasi/wasi-sdk.tar.gz
	wget -c -O ~/Downloads/wasi/wasi-sdk.tar.gz https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_MAJOR}/wasi-sdk-${WASI_VERSION}-$OS.tar.gz || exit 1
	rm -f ~/Downloads/wasi/wasi-sysroot.tar.gz
	wget -c -O ~/Downloads/wasi/wasi-root.tar.gz https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_MAJOR}/wasi-sysroot-${WASI_VERSION}.tar.gz || exit 1
	(
		cd ~/Downloads/wasi
		tar xzvf wasi-sdk.tar.gz
		tar xzvf wasi-root.tar.gz
		mv wasi-sysroot wasi-sysroot-${WASI_VERSION}
	)
fi

cp -f dist/plugins-cfg/plugins.wasi.cfg plugins.cfg

ERR=0
./configure --with-static-themes --without-gperf --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi-api --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl
make -j
R2V=`./configure -qV`
D="radare2-$R2V-wasi-api"
mkdir -p $D
for a in ${TOOLS} ; do
	make -C binr/$a
	cp -f binr/$a/$a.wasm $D || ERR=1
done
zip -r "$D".zip $D
exit $ERR
