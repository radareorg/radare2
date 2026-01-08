#!/bin/sh

. `dirname $0`/wasi-env.sh
. `dirname $0`/wasi-common.sh

TOOLS="rax2 rafs2 radiff2 rahash2 radare2 rasm2 rabin2 rafind2"

# Setup WASI SDK
wasi_setup_sdk

# Setup plugins
wasi_setup_plugins

# Configure and build
# XXX gperf-builds are broken
# ./configure --with-static-themes --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl
./configure --with-static-themes --without-gperf --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl --without-zip || exit 1

make -j || exit 1

# Build tools and package
R2V=`./configure -qV`
D="radare2-$R2V-wasi"

wasi_build_tools "$TOOLS" "$D"
ERR=$?

# Optional optimization step (currently disabled)
# for a in $D/*.wasm ; do
# 	echo "Optimizing $a ..."
# 	wasm-opt -o $a.o3.wasm -O3 $a
# done

zip -r "$D".zip $D
exit $ERR
