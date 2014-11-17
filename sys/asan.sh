#!/bin/sh
export CFLAGS="-fsanitize=address -lasan"
export LDFLAGS="-lasan"
echo 'int main(){return 0;}' > .a.c
[ -z "${CC}" ] && CC=gcc
${CC} ${CFLAGS} ${LDFLAGS} -o .a.out .a.c
RET=$?
rm -f .a.out .a.c
if [ $RET != 0 ]; then
	echo "Your compiler doesn't supports ASAN."
	exit 1
fi
exec sys/install.sh $@
