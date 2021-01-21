#!/bin/sh

WRKDIR=/tmp
SDKDIR=${WRKDIR}/r2-sdk
if [ -n "$1" ]; then
	if [ -f "$1" ]; then
		echo "Target directory exists. Cant build the SDK in there"
		exit 1
	fi
	SDKDIR="$1"
fi

# Builds an SDK to build stuff for rbin
export CFLAGS="-Os -fPIC"
make mrproper
if [ -z "${R2_PLUGINS_CFG}" ]; then
	R2_PLUGINS_CFG=dist/plugins-cfg/plugins.bin.cfg
fi
cp -f "${R2_PLUGINS_CFG}" plugins.cfg
#./configure-plugins
./configure --prefix="$PREFIX" --with-libr --without-libuv --without-gpl || exit 1
#--disable-loadlibs || exit 1
make -j8 || exit 1
rm -rf "${SDKDIR}"
mkdir -p "${SDKDIR}"/lib
rm -f libr/libr.a
cp -rf libr/include "${SDKDIR}"
mkdir -p "${SDKDIR}/include/sdb"
cp -rf shlr/sdb/src/*.h "${SDKDIR}/include/sdb/"
FILES=`find libr shlr -iname '*.a'`
cp -f ${FILES} "${SDKDIR}"/lib
OS=`uname`
AR=`uname -m`
SF=r2sdk-${OS}-${AR}

(
cd "${WRKDIR}"
mv r2-sdk "${SF}"
zip -r "${SF}".zip "${SF}"
)
mv "${WRKDIR}/${SF}" .
mv "${WRKDIR}/${SF}".zip .
ln -fs "${SF}" r2sdk
