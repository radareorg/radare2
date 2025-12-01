#!/bin/sh

. `dirname $0`/wasi-env.sh

echo "WASI_SDK=$WASI_SDK"

# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

export CC="${WASI_SDK}/bin/clang --target=wasm32-wasi -Os"
export AR="${WASI_SDK}/bin/llvm-ar"

CFGFLAGS="./configure --prefix=/usr --disable-debugger --with-compiler=wasi --with-static-themes --with-libr --with-wasi-browser --without-fork --with-ostype=wasi --with-checks-level=0 --disable-threads --without-dylink --without-gpl"

make mrproper
cp -f dist/plugins-cfg/plugins.wasi.cfg plugins.cfg
./configure-plugins

./configure ${CFGFLAGS} && \
	make -s -j ${MAKE_JOBS} DEBUG=0
make -j
R2V=`./configure -qV`
D="radare2-$R2V-wasi-browser"
mkdir -p $D
for a in ${TOOLS} ; do
	make -C binr/$a
	cp -f binr/$a/$a.wasm $D || ERR=1
done
# for a in $D/*.wasm ; do
# 	echo "Optimizing $a ..."
# 	wasm-opt -o $a.o3.wasm -O3 $a
# done
zip -r "$D".zip $D
exit $ERR
