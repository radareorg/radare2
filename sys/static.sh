#!/bin/sh

MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

if [ `uname` = Darwin ]; then
	STRIP="strip"
else
	STRIP="strip -s"
fi

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
	export CFLAGS="-fPIC"
	cp -f plugins.static.cfg plugins.cfg
#-D__ANDROID__=1"
	./configure-plugins || exit 1
	./configure --prefix="$PREFIX" --with-nonpic --without-pic --disable-loadlibs || exit 1
fi
${MAKE} -j 8 || exit 1
BINS="rarun2 rasm2 radare2 ragg2 rabin2 rax2 rahash2 rafind2 rasign2 r2agent radiff2"
# shellcheck disable=SC2086
for a in ${BINS} ; do
(
	cd binr/$a
	${MAKE} clean
	#LDFLAGS=-static ${MAKE} -j2
	${MAKE} -j4 || exit 1
	${STRIP} $a
)
done

rm -rf r2-static
mkdir r2-static || exit 1
${MAKE} install DESTDIR="${PWD}/r2-static" || exit 1

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
	-I r2-static/usr/include/libr \
	r2-static/usr/lib/libr.a
res=$?
if [ $? = 0 ]; then
	echo SUCCESS
else
	echo FAILURE
fi

exit $res
