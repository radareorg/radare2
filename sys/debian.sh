#!/bin/sh
# run this from a debian system, docker is fine :)

uname -a

ARG=$1

if [ "$ARG" = "arm64" ]; then
  ARCH=arm64
elif [ "$ARG" = "amd64" ]; then
  ARCH=amd64
  export CFLAGS="-Werror"
elif [ "$ARG" = "i386" ]; then
  ARCH=i386
  export CFLAGS="-m32 -Werror"
  export LDFLAGS=-m32
else
  CFGARGS=$*
fi

if [ -z "${ARCH}" ]; then
  ARCH=`uname -m`
fi

if [ "${ARCH}" = "x86_64" ]; then
  ARCH=amd64
fi
if [ "${ARCH}" = "aarch64" ]; then
  ARCH=arm64
fi
export ARCH

echo "[debian] preparing radare2 package..."
PKGDIR=dist/debian/radare2/root
DEVDIR=dist/debian/radare2-dev/root

# clean
rm -rf "${PKGDIR}" "${DEVDIR}"

. `dirname $0`/make-jobs.inc.sh

type fakeroot > /dev/null 2>&1
if [ $? = 0 ]; then
FAKEROOT=fakeroot
else
FAKEROOT=
fi

export CFLAGS="-Wno-cpp -Wno-unused-result ${CFLAGS} -O2"
# build
./configure --prefix=/usr --with-checks-level=0 ${CFGARGS}
[ $? != 0 ] && exit 1
make -j4
[ $? != 0 ] && exit 1
$FAKEROOT make install DESTDIR="${PWD}/${PKGDIR}"
[ $? != 0 ] && exit 1

# dev-split
mkdir -p "${DEVDIR}/usr/include"
mv "${PKGDIR}/usr/include/"* "${DEVDIR}/usr/include"
mkdir -p "${DEVDIR}/usr/lib"
mv "${PKGDIR}/usr/lib/"lib*a "${DEVDIR}/usr/lib"
mv "${PKGDIR}/usr/lib/pkgconfig" "${DEVDIR}/usr/lib"

# strip
for a in ${PKGDIR}/usr/bin/* ; do
  echo "[debian] strip $a"
  strip --strip-all "$a" 2> /dev/null || true
done
for a in ${PKGDIR}/usr/lib/libr*.so.* ; do
  echo "[debian] strip $a"
  strip --strip-unneeded "$a" 2> /dev/null || true
done
for a in ${PKGDIR}/usr/lib/radare2/*/* ; do
  echo "[debian] strip $a"
  strip --strip-unneeded "$a" 2> /dev/null || true
done

# r2book
echo "[debian] download latest r2book info..."
wget -P "${PKGDIR}/usr/share/info/" \
  "https://github.com/radareorg/radare2-book/releases/latest/download/r2book.info.gz"

# packages
echo "[debian] building radare2 package..."
$FAKEROOT make -C dist/debian/radare2 ARCH=${ARCH}
cp -f dist/debian/radare2/*.deb .

echo "[debian] building radare2-dev package..."
$FAKEROOT make -C dist/debian/radare2-dev ARCH=${ARCH}
cp -f dist/debian/radare2-dev/*.deb .
