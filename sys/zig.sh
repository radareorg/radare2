#!/bin/sh

ARG="$1"

TARGETS="
	native
	clean

	arm-linux
	arm64-linux
	amd64-linux
	riscv64-linux
	mips-linux
	sparcv9-linux
	ppc-linux
	ppc64-linux
	wasm32-wasi

Experimental:
	arm64-macos
	amd64-macos
	amd64-netbsd
"

if [ -z "$ARG" ]; then
	echo "Usage: sys/zig.sh [target]"
	echo "Targets:$TARGETS"
#echo "CPUS: x86_64 arm aarch64 i386 riscv64 wasm32"
#echo "OSS: linux macos windows freebsd netbsd dragonfly UEFI"
	exit 1
fi
TARGET="$ARG"
OSTYPE=gnulinux
#export CC="zig cc -std=c11"
#export LD="zig cc"

CFGFLAGS=""

case "$TARGET" in
clean)
	make clean > /dev/null
	exit 0
	;;
amd64-darwin|x86_64-darwin|amd64-macos|x86_64-macos)
	TARGET="x86_64-macos"
	OSTYPE=darwin
	CFGFLAGS="--disable-debugger" # ptrace.h is missing
	;;
arm64-darwin|aarch64-darwin|arm64-macos|aarch64-macos)
	TARGET="aarch64-macos"
	OSTYPE=darwin
	CFGFLAGS="--disable-debugger"
	;;
wasm32|wasm|wasm32-wasi|wasi)
	TARGET="wasm32-wasi"
	;;
arm-linux|arm32-linux)
	TARGET="arm-linux"
	;;
arm64-linux|aarch64-linux)
	TARGET="aarch64-linux"
	;;
ppc-linux|powerpc-linux)
	TARGET="powerpc-linux"
	;;
ppc64-linux|powerpc64-linux)
	TARGET="powerpc64-linux"
	;;
amd64-linux|x86_64-linux|x64-linux)
	TARGET="x86_64-linux"
	;;
riscv-linux|riscv64-linux)
	TARGET="riscv64-linux"
	;;
amd64-freebsd|x86_64-freebsd|x64-freebsd)
	TARGET="x86_64-freebsd"
	;;
mips-linux|mips64-linux)
	TARGET="mips-linux"
	;;
amd64-netbsd)
	TARGET="x86_64-netbsd"
	;;
native)
	TARGET=""
	;;
*)
	echo "Unknown target $TARGET"
	;;
esac

#export CFLAGS="-Oz"
#export LDFLAGS="-flto"

if [ -z "${TARGET}" ]; then
	export CC="zig cc"
	export LD="zig cc"
else
	export CC="zig cc -target ${TARGET}"
	export LD="zig cc -target ${TARGET}"
fi
# nollvm
#export CC="$CC -fstage1 -fno-LLVM"
#export LD="$LD -fstage1 -fno-LLVM"
export EXT_SO=so
export AR="zig ar"
export RANLIB="zig ranlib"
rm -f libr/include/r_version.h
# ./configure --host=aarch64-gnu-linux --with-ostype=linux
./configure --with-ostype=$OSTYPE ${CFGFLAGS} || exit 1
time make -j
