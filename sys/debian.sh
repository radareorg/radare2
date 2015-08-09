#!/bin/sh
# run this from a debian system, docker is fine :)
#sys/build.sh

# inspired by ios-sdk.sh
echo "[debian] preparing radare2 package..."
PKGDIR=sys/debian/radare2/root
DEVDIR=sys/debian/radare2-dev/root
rm -rf "${PKGDIR}" "${DEVDIR}"
make install DESTDIR="${PWD}/${PKGDIR}"
mkdir -p "${DEVDIR}/usr/include"
mv "${PKGDIR}/usr/include/"* "${DEVDIR}/usr/include"
mkdir -p "${DEVDIR}/usr/lib"
mv "${PKGDIR}/usr/lib/"lib*a "${DEVDIR}/usr/lib"
mv "${PKGDIR}/usr/lib/pkgconfig" "${DEVDIR}/usr/lib"
for a in ${PKGDIR}/usr/bin/* ; do
   echo "[debian] strip $a"
   strip -s "$a" || strip "$a"
done

echo "[debian] building radare2 package..."
make -C sys/debian/radare2

echo "[debian] building radare2-dev package..."
make -C sys/debian/radare2-dev
