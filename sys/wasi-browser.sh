#!/bin/sh

. `dirname $0`/wasi-env.sh

echo "WASI_SDK=$WASI_SDK"

TOOLS="rax2 radiff2 rahash2 radare2 rasm2 rabin2 rafind2"

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

# Ensure WASI SDK is in PATH
export PATH="${WASI_SDK}/bin:${PATH}"

# Sanity check: test if the WASI toolchain can create executables
echo "Checking WASI toolchain..."
echo "int main() { return 0; }" > /tmp/wasi_test.c
if ! ${WASI_SDK}/bin/clang --target=wasm32-wasi /tmp/wasi_test.c -o /tmp/wasi_test.wasm 2>/dev/null; then
	echo "ERROR: WASI toolchain cannot create executables"
	echo "Command failed: clang --target=wasm32-wasi /tmp/wasi_test.c -o /tmp/wasi_test.wasm"
	rm -f /tmp/wasi_test.c /tmp/wasi_test.wasm
	exit 1
fi
rm -f /tmp/wasi_test.c /tmp/wasi_test.wasm
echo "WASI toolchain OK"

cp -f dist/plugins-cfg/plugins.wasi.cfg plugins.cfg

# export CC="${WASI_SDK}/bin/clang -D
ERR=0
# XXX gperf-builds are broken
# ./configure --with-static-themes --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl
./configure --with-static-themes --without-gperf --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl --with-wasm-browser || exit 1
make -j || ERR=1
R2V=`./configure -qV`
D="radare2-$R2V-wasm-browser"
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
