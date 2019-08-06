#!/bin/sh

[ -z "${STATIC_BINS}" ] && STATIC_BINS=0

case "$(uname)" in
Linux)
	LDFLAGS="${LDFLAGS} -lpthread -ldl -lutil -lm"
	;;
OpenBSD)
	LDFLAGS="${LDFLAGS} -lpthread -lkvm -lutil -lm"
	;;
esac
MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd "$(dirname "$PWD/$0")" ; cd ..

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
DOCFG=1
if [ 1 = "${DOCFG}" ]; then
	# build
	if [ -f config-user.mk ]; then
		${MAKE} mrproper > /dev/null 2>&1
	fi
	export CFLAGS="${CFLAGS} -fPIC"
	#cp -f plugins.static.cfg plugins.cfg
	cp -f plugins.static.nogpl.cfg plugins.cfg
	./configure-plugins || exit 1
	#./configure --prefix="$PREFIX" --without-gpl --with-libr --without-libuv --disable-loadlibs || exit 1
	./configure --prefix="$PREFIX" --without-gpl --with-libr --without-libuv || exit 1
fi
${MAKE} -j 8 || exit 1
BINS="rarun2 rasm2 radare2 ragg2 rabin2 rax2 rahash2 rafind2 r2agent radiff2"
# shellcheck disable=SC2086
for a in ${BINS} ; do
(
	cd binr/$a
	${MAKE} clean
	if [ "`uname`" = Darwin ]; then
		${MAKE} -j4 || exit 1
	else
		if [ "${STATIC_BINS}" = 1 ]; then
			CFLAGS=-static LDFLAGS=-static ${MAKE} -j4 || exit 1
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
	CC=gcc
fi
${CC} .test.c \
	${CFLAGS} \
	-I r2-static/usr/include/libr \
	r2-static/usr/lib/libr.a ${LDFLAGS}
res=$?
if [ $res = 0 ]; then
	echo SUCCESS
	rm a.out
else
	echo FAILURE
fi

rm .test.c
exit $res
