#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

export CC="emcc --ignore-dynamic-linking"
export AR="emar"

CFGFLAGS="./configure --prefix=/usr --without-ewf --without-gmp"

make mrproper
cp -f plugins.tiny.cfg plugins.cfg
./configure-plugins

./configure ${CFGFLAGS} && \
	make -s -j ${MAKE_JOBS} DEBUG=0
