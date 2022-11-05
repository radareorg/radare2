#!/bin/sh

ARG="$1"

TARGETS="
	arm64-linux
	amd64-linux
	native
"

if [ -z "$ARG" ]; then
	echo "Usage: sys/zig.sh [cpu] [os]"
	echo "CPUS: x86_64 arm aarch64 i386 riscv64 wasm32"
	echo "OSS: linux macos windows freebsd netbsd dragonfly UEFI"
	exit 1
fi
#export CC="zig cc -std=c11"
#export LD="zig cc"

case "$TARGET" in
arm64-linux|aarch64-linux)
	TARGET="aarch64-linux"
	;;
amd64-linux|x86_64-linux|x64-linux)
	TARGET="aarch64-linux"
	;;
amd64-freebsd|x86_64-freebsd|x64-freebsd)
	TARGET="x86_64-freebsd"
	;;
native)
	TARGET=""
	;;
*)
	echo "Unknown target"
	;;
esac

TARGET="riscv64-windows"

export CFLAGS="-Oz"
export LDFLAGS="-flto"

if [ -z "${TARGET}" ]; then
	export CC="zig cc"
	export LD="zig cc"
else
	export CC="zig cc -target ${TARGET}"
	export LD="zig cc -target ${TARGET}"
fi
export EXT_SO=so
export AR="zig ar"
export RANLIB="zig ranlib"
rm -f libr/include/r_version.h
# ./configure --host=aarch64-gnu-linux --with-ostype=linux
./configure --with-ostype=gnulinux
time make -j
