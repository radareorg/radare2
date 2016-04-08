#!/bin/sh

CHECKERS="alpha.core.TestAfterDivZero
alpha.core.BoolAssignment
alpha.core.CastToStruct
alpha.core.FixedAddr
alpha.core.IdenticalExpr
alpha.core.PointerArithm
alpha.core.PointerSub
alpha.core.SizeofPtr
alpha.core.TestAfterDivZero
alpha.deadcode.UnreachableCode
alpha.security.ArrayBoundV2
alpha.security.MallocOverflow
alpha.security.ReturnPtrRange
alpha.security.taint.TaintPropagation
alpha.unix.Chroot
alpha.unix.PthreadLock
alpha.unix.SimpleStream
alpha.unix.cstring.BufferOverlap
alpha.unix.cstring.NotNullTerminated
alpha.unix.cstring.OutOfBounds
security.FloatLoopCounter
"

for a in ${CHECKERS} ; do
	PLUGINS="${PLUGINS} -enable-checker $a"
done

if [ -z "${MAKE}" ]; then
	MAKE=make
	gmake --help >/dev/null 2>&1
	[ $? = 0 ] && MAKE=gmake
	export MAKE="${MAKE}"
fi
scan-build echo >/dev/null
[ $? = 0 ] || exit 1

# find root
cd `dirname $PWD/$0` ; cd ..

# build
${MAKE} mrproper > /dev/null 2>&1
rm -rf scan-log
scan-build ./configure --prefix=/usr
scan-build ${PLUGINS} -o ${PWD}/clang-log ${MAKE} -j 4
echo Check ${PWD}/clang-log
