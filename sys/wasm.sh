#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

export CC="emcc -Os -s WASM=1 -s SIDE_MODULE=1"
export AR="emar"

CFGFLAGS="./configure --prefix=/usr --disable-debugger --with-compiler=wasm --with-libr"

make mrproper
cp -f dist/plugins-cfg/plugins.emscripten.cfg plugins.cfg
./configure-plugins

./configure ${CFGFLAGS} --host=wasm && \
	make -s -j ${MAKE_JOBS} DEBUG=0
