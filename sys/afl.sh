#!/bin/sh
export CC="afl-clang"
# export AFL_USE_ASAN=1
if [ -d /usr/lib/afl ]; then
	export AFL_PATH=/usr/lib/afl
fi
echo 'int main(){return 0;}' > .a.c
[ -z "${CC}" ] && CC=gcc
${CC} ${CFLAGS} ${LDFLAGS} -o .a.out .a.c
RET=$?
rm -f .a.out .a.c
if [ $RET != 0 ]; then
	echo "Your compiler doesn't supports AFL"
	exit 1
fi
exec sys/install.sh $*
