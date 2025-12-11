#!/bin/sh

. `dirname $0`/wasi-env.sh

echo "WASI_SDK=$WASI_SDK"

TOOLS="rax2 rafs2 radiff2 rahash2 radare2 rasm2 rabin2 rafind2"
ARCH=x86_64

if [ ! -d "$WASI_SDK" ]; then
	#OS=linux,macos,mingw
	OS=`uname`
	case "$OS" in
	linux|Linux) OS=linux ; ;;
	darwin|Darwin) OS=macos ; ;;
	windows|Windows) OS=mingw ; ;;
	esac
	OS="$ARCH-$OS"
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

# export CC="${WASI_SDK}/bin/clang -D
ERR=0
# XXX gperf-builds are broken
# ./configure --with-static-themes --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl
./configure --with-static-themes --without-gperf --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl
make -j
#|| ERR=1 ld: unknown option: --whole-archive
R2V=`./configure -qV`
D="radare2-$R2V-wasi"
mkdir -p $D
for a in ${TOOLS} ; do
	make -C binr/$a || ERR=1
	cp -f binr/$a/$a.wasm $D || ERR=1
done
# for a in $D/*.wasm ; do
# 	echo "Optimizing $a ..."
# 	wasm-opt -o $a.o3.wasm -O3 $a
# done
zip -r "$D".zip $D
exit $ERR
