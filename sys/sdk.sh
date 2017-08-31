#!/bin/sh

SDKDIR=/tmp/r2-sdk
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
cp -f plugins.bin.cfg plugins.cfg
#./configure-plugins
./configure --prefix="$PREFIX" --with-nonpic --without-pic --without-gpl || exit 1
#--disable-loadlibs || exit 1
make -j8 || exit 1
rm -rf "${SDKDIR}"
mkdir -p "${SDKDIR}"/lib
rm -f libr/libr.a
cp -rf libr/include "${SDKDIR}"
FILES=`find libr shlr -iname '*.a'`
cp -f ${FILES} "${SDKDIR}"/lib
OS=`uname`
AR=`uname -m`
SF=r2sdk-${OS}-${AR}

(
cd ${SDKDIR}/..
mv r2-sdk ${SF}
zip -r ${SF}.zip ${SF}
)
mv ${SDKDIR}/../${SF}.zip .
