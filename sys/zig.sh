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
	i386-windows
	amd64-windows
	arm64-windows

See \`zig targets\` for more details.
"

if [ -z "$ARG" ]; then
	echo "Usage: sys/zig.sh [target]"
	echo "Environment:"
	echo "	STATIC=0|1    # build r2 statically"
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
	TARGET="wasm32-wasi-musl"
	;;
arm-linux|arm32-linux)
	TARGET="arm-linux"
	;;
arm64-linux|aarch64-linux)
	TARGET="aarch64-linux-musl"
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
ios)
	TARGET="aarch64-ios-none" #aarch64-linux-android"
	OSTYPE=darwin
	CFGFLAGS="--disable-debugger"
	;;
w32|wXP|wxp|i386-windows)
	TARGET="i386-windows-gnu"
	OSTYPE=windows
	;;
w64|windows)
	TARGET="x86_64-windows-gnu"
	OSTYPE=windows
	;;
arm64-windows|aarch64-windows)
	TARGET="aarch64-windows-gnu"
	OSTYPE=windows
	;;
amd64-netbsd)
	## missing libc
	TARGET="x86_64-netbsd.9"
	;;
wip)
	TARGET="aarch64-netbsd.9-musl"
	;;
native)
	TARGET=""
	;;
*)
	echo "Unknown target $TARGET"
	;;
esac

# seems to be problematic, better leave cflags to the user
#export CFLAGS="-Oz"
#export LDFLAGS="-flto"

if [ -z "${TARGET}" ]; then
	export CC="zig cc"
	export LD="zig cc"
else
	export CC="zig cc -target ${TARGET}"
	export LD="zig cc -target ${TARGET}"
fi
# nollvm doesnt work with all targets
#export CC="$CC -fstage1 -fno-LLVM"
#export LD="$LD -fstage1 -fno-LLVM"
case "$OSTYPE" in
macos|ios|darwin)
	export EXT_SO=dylib
	;;
windows)
	export EXT_AR=lib
	export EXT_SO=dll
	;;
*)
	export EXT_SO=so
	;;
esac
export AR="zig ar"
export RANLIB="zig ranlib"
if [ "$STATIC" = 1 ]; then
	CFGFLAGS="--with-libr"
	export PARTIALLD="${CC} -r -Wl,--whole-archive -c"
fi

RUN_CONFIGURE=1
if [ "$RUN_CONFIGURE" = 1 ]; then
	rm -f libr/include/r_version.h
	# ./configure --host=aarch64-gnu-linux --with-ostype=linux
	./configure --with-ostype=$OSTYPE ${CFGFLAGS} || exit 1
fi
if [ "${STATIC}" = 1 ]; then
	time make -j PARTIALLD="${PARTIALLD}"
else
	time make -j
fi
