#!/bin/sh
MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake
scan-build echo >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake

# find root
cd `dirname $PWD/$0` ; cd ..

# build
if [ -f config-user.mk ]; then
	${MAKE} mrproper > /dev/null 2>&1
fi
./configure --prefix=/usr && \
scan-build -o sys/clang-log ${MAKE} -j 4
echo Check ${PWD}/clang-log
