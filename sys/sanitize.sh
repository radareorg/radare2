#!/bin/sh
# SANITIZE="address leak memory undefined"
# SANITIZE="address signed-integer-overflow"  # Faster build
SANITIZE=${SANITIZE:="address undefined signed-integer-overflow"}

printf "\033[32m"
echo "========================================================================="
printf "\033[33m"
echo "Sanitize build script can be configured with the SANITIZE environment variable."
echo "Use one of the following words to specify which sanitizers to use:"
echo "  - address     - detect memory errors"
echo "  - leak        - find memory leaks"
echo "  - memory      - detect uninitialized reads"
echo "  - undefined   - find undefined behaviour"
echo "  - ..."
echo "For more information:"
echo "  http://clang.llvm.org/docs/UsersManual.html#controlling-code-generation"
echo "For example:"
echo "  $ SANITIZE='leak memory address' sys/sanitize.sh"
echo "Current value:"
echo "  SANITIZE=${SANITIZE}"
printf "\033[32m"
echo "========================================================================="
printf "\033[0m"
sleep 1

# memory leaks are detected by default, can only be disabled via env var
HAVE_LEAKS=1
for a in $SANITIZE ; do
	export CFLAGS="${CFLAGS} -fsanitize=$a"
	if [ "$a" = leak ]; then
		HAVE_LEAKS=0
	fi
done
if [ "${HAVE_LEAKS}" = 0 ]; then
	export ASAN_OPTIONS=detect_leaks=0
fi
if [ "`uname`" != Darwin ]; then
	for a in $SANITIZE ; do
		export LDFLAGS="${LDFLAGS} -fsanitize=$a"
	done
fi

echo 'int main(){return 0;}' > .a.c
[ -z "${CC}" ] && CC=gcc
${CC} ${CFLAGS} ${LDFLAGS} -o .a.out .a.c
RET=$?
rm -f .a.out .a.c
if [ "$RET" != 0 ]; then
	echo "Your compiler doesn't support a sanitizer in SANITIZE."
	exit 1
fi

SCRIPT=install.sh
if [ "$1" = "-u" ]; then
	shift
	SCRIPT=user.sh
fi
exec sys/${SCRIPT} $*
