#!/bin/sh

PLUGINS="-enable-checker alpha.core.TestAfterDivZero"
PLUGINS="${PLUGINS} -enable-checker alpha.core.BoolAssignment"
PLUGINS="${PLUGINS} -enable-checker alpha.core.CastToStruct"
PLUGINS="${PLUGINS} -enable-checker alpha.core.FixedAddr"
PLUGINS="${PLUGINS} -enable-checker alpha.core.IdenticalExpr"
PLUGINS="${PLUGINS} -enable-checker alpha.core.PointerArithm"
PLUGINS="${PLUGINS} -enable-checker alpha.core.PointerSub"
PLUGINS="${PLUGINS} -enable-checker alpha.core.SizeofPtr"
PLUGINS="${PLUGINS} -enable-checker alpha.core.TestAfterDivZero"
PLUGINS="${PLUGINS} -enable-checker alpha.deadcode.UnreachableCode"
PLUGINS="${PLUGINS} -enable-checker alpha.security.ArrayBoundV2"
PLUGINS="${PLUGINS} -enable-checker alpha.security.MallocOverflow"
PLUGINS="${PLUGINS} -enable-checker alpha.security.ReturnPtrRange"
PLUGINS="${PLUGINS} -enable-checker alpha.security.taint.TaintPropagation"
PLUGINS="${PLUGINS} -enable-checker alpha.unix.Chroot"
PLUGINS="${PLUGINS} -enable-checker alpha.unix.PthreadLock"
PLUGINS="${PLUGINS} -enable-checker alpha.unix.SimpleStream"
PLUGINS="${PLUGINS} -enable-checker alpha.unix.cstring.BufferOverlap"
PLUGINS="${PLUGINS} -enable-checker alpha.unix.cstring.NotNullTerminated"
PLUGINS="${PLUGINS} -enable-checker alpha.unix.cstring.OutOfBounds"
PLUGINS="${PLUGINS} -enable-checker security.FloatLoopCounter"


MAKE=make
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake
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
