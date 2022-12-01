#!/bin/sh

[ -z "${STATIC_BINS}" ] && STATIC_BINS=0

if [ "$1" = "--help" ]; then
	echo "Usage: sys/static.sh [--help,--meson]"
	exit 0
fi

if [ "$1" = "--meson" ]; then
        CFLAGS="-static" LDFLAGS="-static" meson --prefix=${HOME}/.local --buildtype release --default-library static build
        ninja -C build && ninja -C build install
	exit $?
fi

case "$(uname)" in
Linux)
	LDFLAGS="${LDFLAGS} -lpthread -ldl -lutil -lm"
	if [ "$NOLTO" != 1 ]; then
		CFLAGS="${CFLAGS} -flto"
		LDFLAGS="${LDFLAGS} -flto"
	fi
	if [ -n "`gcc -v 2>&1 | grep gcc`" ]; then
		export AR=gcc-ar
	fi
	CFLAGS_STATIC=-static
	;;
Darwin)
	CFLAGS="${CFLAGS} -flto"
	LDFLAGS="${LDFLAGS} -flto"
	CFLAGS_STATIC=""
	;;
DragonFly|OpenBSD)
	LDFLAGS="${LDFLAGS} -lpthread -lkvm -lutil -lm"
	CFLAGS_STATIC=-static
	;;
esac
MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd "$(dirname "$PWD/$0")" ; cd ..

musl-gcc --help > /dev/null 2>&1
if [ $? = 0 ]; then
	CFGARGS=--with-compiler=musl-gcc
	export CC="musl-gcc"
fi

ccache --help > /dev/null 2>&1
if [ $? = 0 ]; then
	[ -z "${CC}" ] && CC=gcc
	CC="ccache ${CC}"
	export CC
fi
if [ -n "$1" ]; then
	PREFIX="$1"
else
	PREFIX=/usr
fi
# CFGARGS=--disable-loadlibs
# CFGARGS=--without-openssl
DOCFG=1
if [ 1 = "${DOCFG}" ]; then
	# build
	if [ -f config-user.mk ]; then
		${MAKE} mrproper > /dev/null 2>&1
	fi
	export CFLAGS="${CFLAGS} -fPIC"
	export CFGARGS="$CFGARGS --with-static-themes"
	cp -f dist/plugins-cfg/plugins.static.nogpl.cfg plugins.cfg
	./configure-plugins || exit 1
	./configure --prefix="$PREFIX" --without-gpl --with-libr $CFGARGS || exit 1
fi
${MAKE} -j 8 || exit 1
BINS="rarun2 r2pm rasm2 radare2 ragg2 rabin2 rax2 rahash2 rafind2 r2agent radiff2 r2r"
# shellcheck disable=SC2086
export CFLAGS="${CFLAGS_STATIC} ${CFLAGS}"
for a in ${BINS} ; do
(
	cd binr/$a
	${MAKE} clean
	if [ "`uname`" = Darwin ]; then
		${MAKE} -j4 || exit 1
	else
		if [ "${STATIC_BINS}" = 1 ]; then
			CFLAGS=${CFLAGS_STATIC} LDFLAGS=${CFLAGS_STATIC} ${MAKE} -j4 || exit 1
		else
			${MAKE} -j4 || exit 1
		fi
	fi
)
done

rm -rf r2-static
mkdir r2-static || exit 1
${MAKE} install DESTDIR="${PWD}/r2-static" || exit 1

echo "Using PREFIX ${PREFIX}"

# testing installation
cat > .test.c <<EOF
#include <r_core.h>
int main() {
	RCore *core = r_core_new ();
	r_core_free (core);
}
EOF
cat .test.c
if [ -z "${CC}" ]; then
	gcc -v > /dev/null 2>&1 && CC=gcc
fi

# static pkg-config linking test
echo "[*] Static building with pkg-config..."
PKG_CONFIG_FLAGS=`
PKG_CONFIG_PATH="${PWD}/r2-static/usr/lib/pkgconfig" \
pkg-config \
  --define-variable="libdir=${PWD}/r2-static/usr/lib" \
  --define-variable="prefix=${PWD}/r2-static/usr" \
  --static --cflags --libs r_core
`

set -x
${CC} .test.c ${PKG_CONFIG_FLAGS} -o r2-pkgcfg-static
res=$?
set +x
if [ $res = 0 ]; then
	echo SUCCESS
	rm -f a.out
else
	echo FAILURE
fi

echo "[*] Static building with libr.a..."
${CC} .test.c \
	${CFLAGS} \
	-I ${PWD}/r2-static/usr/include/libr \
	-I ${PWD}/r2-static/usr/include/libr/sdb \
	r2-static/usr/lib/libr.a ${LDFLAGS}
res=$?
du -hs r2-static/usr/bin/radare2
du -hs a.out
set +x
if [ $res = 0 ]; then
	echo SUCCESS
	rm -f a.out
else
	echo FAILURE
fi

rm -f .test.c
exit $res
