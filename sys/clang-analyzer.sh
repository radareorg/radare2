#!/bin/sh
MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake
scan-build echo >/dev/null
[ $? = 0 ] || exit 1

# find root
cd `dirname $(pwd)/$0` ; cd ..

# build
${MAKE} mrproper > /dev/null 2>&1
rm -rf scan-log
scan-build ./configure --prefix=/usr && \
scan-build -o $(pwd)/clang-log ${MAKE} -j 4
echo Check $(pwd)/clang-log
