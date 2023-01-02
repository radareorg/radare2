#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

export CC="emcc --ignore-dynamic-linking -Os"
export AR="emar"

CFGFLAGS="--prefix=/usr --with-compiler=emscripten"
CFGFLAGS="${CFGFLAGS} --host x86_64-unknown-linux --without-gperf"
CFGFLAGS="${CFGFLAGS} --disable-debugger --with-libr --without-gpl"
CFGFLAGS="${CFGFLAGS} --without-jemalloc"
CFGFLAGS="${CFGFLAGS} --without-fork" # no process support in Emscripten
CFGFLAGS="${CFGFLAGS} --with-static-themes"

make mrproper
cp -f plugins.emscripten.cfg plugins.cfg
./configure-plugins

./configure ${CFGFLAGS} --host=emscripten && \
	make -s -j ${MAKE_JOBS} DEBUG=0

rm -f r2js.zip
zip r2js.zip binr/*/*.js binr/*/*/*.wasm
