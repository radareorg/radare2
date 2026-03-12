#!/bin/sh
# run this from a debian system, docker is fine :)

uname -a

ARG=$1
CFGOSTYPE=

use_zig_target() {
	ZIG_TARGET="$1"
	type zig > /dev/null 2>&1 || {
		echo "ERROR: zig is required for ${ARCH} builds in sys/debian.sh" >&2
		exit 1
	}
	export CC="zig cc -target ${ZIG_TARGET}"
	export LD="zig cc -target ${ZIG_TARGET}"
	export AR="zig ar"
	export RANLIB="zig ranlib"
	[ -z "${PKGCONFIG}" ] && export PKGCONFIG=/usr/bin/false
	CFGOSTYPE="--with-ostype=gnulinux"
}

case "$ARG" in
arm64)
	ARCH=arm64
	;;
amd64)
	ARCH=amd64
	export CFLAGS="-Werror"
	;;
i386)
	ARCH=i386
	export CFLAGS="-Werror"
	use_zig_target x86-linux-gnu
	;;
*)
	CFGARGS=$*
	;;
esac

if [ -z "${ARCH}" ]; then
	ARCH=`uname -m`
fi

case "${ARCH}" in
x86_64)
	ARCH=amd64
	;;
aarch64)
	ARCH=arm64
	;;
esac
export ARCH

echo "[debian] preparing radare2 package..."
PKGDIR=dist/debian/radare2/root
DEVDIR=dist/debian/radare2-dev/root

# clean
rm -rf "${PKGDIR}" "${DEVDIR}"

. `dirname $0`/make-jobs.inc.sh

if [ -z "${MAKE}" ]; then
	MAKE=make
	gmake --help > /dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
fi

type fakeroot > /dev/null 2>&1
if [ $? = 0 ]; then
FAKEROOT=fakeroot
else
FAKEROOT=
fi

export CFLAGS="-Wno-cpp -Wno-unused-result ${CFLAGS} -O2"
# build
./configure --prefix=/usr --with-checks-level=0 ${CFGOSTYPE} ${CFGARGS}
[ $? != 0 ] && exit 1
${MAKE} -j${MAKE_JOBS}
[ $? != 0 ] && exit 1
$FAKEROOT ${MAKE} install DESTDIR="${PWD}/${PKGDIR}"
[ $? != 0 ] && exit 1

# dev-split
mkdir -p "${DEVDIR}/usr/include"
mv "${PKGDIR}/usr/include/"* "${DEVDIR}/usr/include"
mkdir -p "${DEVDIR}/usr/lib"
set -- "${PKGDIR}/usr/lib"/lib*a
if [ -e "$1" ]; then
	mv "$@" "${DEVDIR}/usr/lib"
fi
if [ -d "${PKGDIR}/usr/lib/pkgconfig" ]; then
	mv "${PKGDIR}/usr/lib/pkgconfig" "${DEVDIR}/usr/lib"
fi

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
$FAKEROOT ${MAKE} -C dist/debian/radare2 ARCH=${ARCH}
cp -f dist/debian/radare2/*.deb .

echo "[debian] building radare2-dev package..."
$FAKEROOT ${MAKE} -C dist/debian/radare2-dev ARCH=${ARCH}
cp -f dist/debian/radare2-dev/*.deb .
