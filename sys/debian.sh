#!/bin/sh
# run this from a debian system, docker is fine :)

uname -a

if [ -z "${ARCH}" ]; then
  ARCH=`uname -m`
fi

if [ "${ARCH}" = "x86_64" ]; then
  ARCH=amd64
fi

echo "[debian] preparing radare2 package..."
PKGDIR=sys/debian/radare2/root
DEVDIR=sys/debian/radare2-dev/root

# clean
rm -rf "${PKGDIR}" "${DEVDIR}"

# build
./configure --prefix=/usr > /dev/null
make -j4 > /dev/null
make install DESTDIR="${PWD}/${PKGDIR}" > /dev/null

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

# packages
echo "[debian] building radare2 package..."
make -C sys/debian/radare2 ARCH=${ARCH}
cp -f sys/debian/radare2/*.deb .

echo "[debian] building radare2-dev package..."
make -C sys/debian/radare2-dev ARCH=${ARCH}
cp -f sys/debian/radare2-dev/*.deb .
