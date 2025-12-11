#!/bin/sh

. `dirname $0`/wasi-env.sh
. `dirname $0`/wasi-common.sh

TOOLS="radare2"

# Setup WASI SDK
wasi_setup_sdk

# Setup plugins
wasi_setup_plugins

# Configure and build
./configure --with-static-themes --without-gperf --with-compiler=wasi --disable-debugger --without-fork --with-ostype=wasi-api --with-checks-level=0 --disable-threads --without-dylink --with-libr --without-gpl || exit 1

make -j || exit 1

# Build tools and package
R2V=`./configure -qV`
D="radare2-$R2V-wasi-api"

wasi_build_tools "$TOOLS" "$D"
ERR=$?

zip -r "$D".zip $D
exit $ERR
