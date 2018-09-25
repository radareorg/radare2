#!/bin/sh
# ASAN="address leak memory undefined"
ASAN=${ASAN:="address undefined signed-integer-overflow"}

printf "\033[32m"
echo "========================================================================="
printf "\033[33m"
echo "ASAN build script can be configured with the ASAN environment variable."
echo "Use one of the following words to specify which build flags to use:"
echo "  - address     - set by default, detect overflows"
echo "  - leak        - find memory leaks"
echo "  - memory      - detect uninitialized reads"
echo "  - undefined   - undefined behaviour"
echo "  - ..."
echo "For more information:"
echo "  http://clang.llvm.org/docs/UsersManual.html#controlling-code-generation"
echo "For example:"
echo "  $ ASAN='leak memory address' sys/asan.sh"
echo "Current value:"
echo "  ASAN=${ASAN}"
printf "\033[32m"
echo "========================================================================="
printf "\033[0m"
sleep 1

for a in $ASAN ; do
	export CFLAGS="${CFLAGS} -fsanitize=$a"
done
if [ "`uname`" != Darwin ]; then
	export CFLAGS="${CFLAGS} -lasan"
	export LDFLAGS="-lasan"
fi

echo 'int main(){return 0;}' > .a.c
[ -z "${CC}" ] && CC=gcc
${CC} ${CFLAGS} ${LDFLAGS} -o .a.out .a.c
RET=$?
rm -f .a.out .a.c
if [ "$RET" != 0 ]; then
	echo "Your compiler doesn't support ASAN."
	exit 1
fi

SCRIPT=install.sh
if [ "$1" = "-u" ]; then
	shift
	SCRIPT=user.sh
fi
exec sys/${SCRIPT} $*
