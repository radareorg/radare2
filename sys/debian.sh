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
PKGDIR=dist/debian/radare2/root
DEVDIR=dist/debian/radare2-dev/root

# clean
rm -rf "${PKGDIR}" "${DEVDIR}"

if [ -z "$CFLAGS" ]; then
  export CFLAGS="-O2 -Werror -Wno-cpp"
  export CFLAGS="${CFLAGS} -Wno-unused-result"
## export CFLAGS="${CFLAGS} -Wno-stringop-truncation"
fi
# build
export
./configure --prefix=/usr --with-checks-level=0
[ $? != 0 ] && exit 1
make -j4
[ $? != 0 ] && exit 1
make install DESTDIR="${PWD}/${PKGDIR}"
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

# packages
echo "[debian] building radare2 package..."
make -C dist/debian/radare2 ARCH=${ARCH}
cp -f dist/debian/radare2/*.deb .

echo "[debian] building radare2-dev package..."
make -C dist/debian/radare2-dev ARCH=${ARCH}
cp -f dist/debian/radare2-dev/*.deb .
