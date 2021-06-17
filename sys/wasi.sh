#!/bin/sh

export WASI_SDK=${HOME}/Downloads/wasi/wasi-sdk-12.0
export WASI_SYSROOT=${HOME}/Downloads/wasi/wasi-sysroot

if [ ! -d "$WASI_SDK" ]; then
	#OS=linux,macos,mingw
	OS=`uname`
	case "$OS" in
	linux|Linux) OS=linux ; ;;
	darwin|Darwin) OS=macos ; ;;
	windows|Windows) OS=mingw ; ;;
	esac
	mkdir -p ~/Downloads/wasi
	wget -c -O ~/Downloads/wasi/wasi-sdk.tar.gz https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sdk-12.0-$OS.tar.gz || exit 1
	wget -c -O ~/Downloads/wasi/wasi-root.tar.gz https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sysroot-12.0.tar.gz || exit 1
	(
		cd ~/Downloads/wasi
		tar xzvf wasi-sdk.tar.gz
		tar xzvf wasi-root.tar.gz
	)
fi

export CFLAGS=-D_WASI_EMULATED_SIGNAL

cp dist/plugins-cfg/plugins.wasi.cfg plugins.cfg

# export CC="${WASI_SDK}/bin/clang -D
./configure --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-libuv --without-gpl
make -j
for a in rax2 radare2 rasm2 rabin2 rafind2 ; do
	make -C binr/$a
done
