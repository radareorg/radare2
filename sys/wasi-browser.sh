#!/bin/sh

. `dirname $0`/wasi-env.sh
. `dirname $0`/wasi-common.sh

TOOLS="rax2 rafs2 radiff2 rahash2 radare2 rasm2 rabin2 rafind2"

# Setup WASI SDK
wasi_setup_sdk

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

# Setup plugins
wasi_setup_plugins

# Configure and build
# XXX gperf-builds are broken
# ./configure --with-static-themes --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl
./configure --with-static-themes --without-gperf --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl --with-wasm-browser --without-zip || exit 1

make -j || exit 1

# Build tools and package
R2V=`./configure -qV`
D="radare2-$R2V-wasi-browser"

wasi_build_tools "$TOOLS" "$D"
ERR=$?

# Optional optimization step (currently disabled)
# for a in $D/*.wasm ; do
# 	echo "Optimizing $a ..."
# 	wasm-opt -o $a.o3.wasm -O3 $a
# done

zip -r "$D".zip $D
exit $ERR
