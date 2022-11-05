#!/bin/sh

ARG="$1"

TARGETS="
	arm-linux
	arm64-linux
	amd64-linux
	riscv64-linux
	mips-linux

	arm64-darwin
	amd64-darwin

	native
	clean
"

if [ -z "$ARG" ]; then
	echo "Usage: sys/zig.sh [target]"
	echo "Targets:$TARGETS"
#echo "CPUS: x86_64 arm aarch64 i386 riscv64 wasm32"
#echo "OSS: linux macos windows freebsd netbsd dragonfly UEFI"
	exit 1
fi
TARGET="$ARG"
#export CC="zig cc -std=c11"
#export LD="zig cc"

case "$TARGET" in
clean)
	make clean > /dev/null
	exit 0
	;;
amd64-darwin|x86_64-darwin)
	TARGET="x86_64-darwin"
	;;
arm64-darwin|aarch64-darwin)
	TARGET="aarch64-darwin"
	;;
arm-linux|arm32-linux)
	TARGET="arm-linux"
	;;
arm64-linux|aarch64-linux)
	TARGET="aarch64-linux"
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
./configure --with-ostype=gnulinux || exit 1
time make -j
