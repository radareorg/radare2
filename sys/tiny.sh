#!/bin/sh
# find root
cd "$(dirname "$PWD/$0")" ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

export CC="emcc --ignore-dynamic-linking"
export AR="emar"

CFGFLAGS="--prefix=/usr"

make mrproper
cp -f dist/plugins-cfg/plugins.tiny.cfg plugins.cfg
./configure-plugins

# shellcheck disable=SC2086
./configure ${CFGFLAGS} && \
	make -s -j ${MAKE_JOBS} DEBUG=0

LDFLAGS="${OLD_LDFLAGS}"
