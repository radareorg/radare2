#!/bin/sh

TARGET="$1"

usage() {
	echo "Usage: sys/cross.sh [aarch64-linux-gnu|arm64-linux|mipsbe|mips-linux-gnu|clean]"
	echo "Environment:"
	echo "	CROSS=aarch64-linux-gnu-    # toolchain prefix"
	echo "	CC=aarch64-linux-gnu-gcc    # target compiler"
	echo "	HOST_CC=cc                  # build-machine compiler for host tools"
	echo "	PLUGINS_CFG=path            # defaults to plugins.static.nogpl.cfg"
	echo "	CONFIGURE_PLUGINS_ARGS=args # extra configure-plugins arguments"
	echo "	CFGARGS=args                # extra configure arguments"
	echo "	JOBS=-j8                    # make parallelism"
	echo "	CLEAN=0                     # do not clean before configuring"
	echo "	BUILD_R2R=1                 # also build a target r2r binary"
	echo "	R2R_LIBATOMIC=args          # target r2r libatomic flags"
	echo "	NOSTRIP=1                   # do not strip binr/blob/r2blob"
	exit 1
}

find_tool() {
	if command -v "$1" >/dev/null 2>&1; then
		command -v "$1"
		return 0
	fi
	for tool in /usr/bin/"$1"-* /usr/local/bin/"$1"-* ; do
		if [ -x "$tool" ]; then
			echo "$tool"
			return 0
		fi
	done
	return 1
}

need_tool() {
	tool="$1"
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "Missing required tool: $tool"
		exit 1
	fi
}

case "$TARGET" in
-h|--help)
	usage
	;;
clean)
	make clean > /dev/null
	exit $?
	;;
""|aarch64|arm64|aarch64-linux|arm64-linux|aarch64-linux-gnu)
	HOST=aarch64-linux-gnu
	;;
mips|mipsbe|mips-linux|mips-linux-gnu)
	HOST=mips-linux-gnu
	;;
*-)
	CROSS="$TARGET"
	HOST="${TARGET%-}"
	;;
*)
	HOST="$TARGET"
	;;
esac

cd "$(dirname "$PWD/$0")" || exit 1
cd .. || exit 1

MAKE="${MAKE:-make}"
if [ -z "$JOBS" ]; then
	JOBS=-j
else
	case "$JOBS" in
	-j*) ;;
	*) JOBS="-j$JOBS" ;;
	esac
fi

CROSS="${CROSS:-${HOST}-}"
if [ -z "$COMPILER" ]; then
	if [ -f "mk/${HOST}-gcc.mk" ]; then
		COMPILER="${HOST}-gcc"
	else
		COMPILER=gcc
	fi
fi
CC="${CC:-$(find_tool "${CROSS}gcc")}"
AR="${AR:-${CROSS}ar}"
RANLIB="${RANLIB:-${CROSS}ranlib}"
LD="${LD:-${CROSS}ld}"
OBJCOPY="${OBJCOPY:-${CROSS}objcopy}"
STRIP="${STRIP:-${CROSS}strip}"
READELF="${READELF:-${CROSS}readelf}"
HOST_CC="${HOST_CC:-cc}"
PLUGINS_CFG="${PLUGINS_CFG:-dist/plugins-cfg/plugins.static.nogpl.cfg}"

[ -n "$CC" ] || {
	echo "Missing required tool: ${CROSS}gcc"
	exit 1
}

need_tool "$CC"
need_tool "$AR"
need_tool "$RANLIB"
need_tool "$LD"
need_tool "$HOST_CC"

if [ -z "$PKGCONFIG" ]; then
	if [ -x /usr/bin/false ]; then
		PKGCONFIG=/usr/bin/false
	else
		PKGCONFIG=/bin/false
	fi
fi

export CC AR RANLIB LD OBJCOPY STRIP PKGCONFIG HOST_CC
export USE_PIE=0
export CFLAGS="${CFLAGS} -O2"

run_make() {
	${MAKE} ${JOBS} \
		CC="${CC}" \
		AR="${AR}" \
		RANLIB="${RANLIB}" \
		LD="${LD}" \
		OBJCOPY="${OBJCOPY}" \
		USE_PIE=0 \
		"$@"
}

run_make_blob() {
	if [ -z "$BLOB_LDFLAGS" ]; then
		libatomic="$(sed -n 's/^LIBATOMIC=//p' config-user.mk | tail -n 1)"
		BLOB_LDFLAGS="-static ../../libr/libr.a -lm -ldl -pthread -lutil ${libatomic}"
	fi
	run_make -C binr/blob LDFLAGS="$BLOB_LDFLAGS"
}

run_make_r2r() {
	if [ -z "$R2R_LIBATOMIC" ]; then
		R2R_LIBATOMIC="$(sed -n 's/^LIBATOMIC=//p' config-user.mk | tail -n 1)"
	fi
	run_make -C binr/r2r LIBATOMIC="$R2R_LIBATOMIC"
}

if [ "${CLEAN}" != 0 ]; then
	${MAKE} clean > /dev/null 2>&1 || true
fi

rm -f libr/include/r_version.h
cp -f "$PLUGINS_CFG" plugins.cfg || exit 1
# shellcheck disable=SC2086
./configure-plugins $CONFIGURE_PLUGINS_ARGS || exit 1

# shellcheck disable=SC2086
./configure \
	--host="$HOST" \
	--with-ostype=gnulinux \
	--with-compiler="$COMPILER" \
	--with-libr \
	--with-static-themes \
	--without-gpl \
	$CFGARGS || exit 1

run_make libr/include/r_version.h || exit 1
run_make -C shlr sdbs || exit 1
run_make -C shlr/zip || exit 1
run_make -C libr/util || exit 1
run_make -C libr/socket || exit 1
run_make -C shlr || exit 1
run_make -C libr || exit 1
run_make_blob || exit 1
if [ "${BUILD_R2R}" = 1 ]; then
	run_make_r2r || exit 1
fi

if [ "${NOSTRIP}" != 1 ] && command -v "$STRIP" >/dev/null 2>&1; then
	"$STRIP" -s binr/blob/r2blob 2> /dev/null || true
	if [ "${BUILD_R2R}" = 1 ]; then
		"$STRIP" -s binr/r2r/r2r 2> /dev/null || true
	fi
fi

echo "Built binr/blob/r2blob for $HOST"
if command -v "$READELF" >/dev/null 2>&1; then
	if "$READELF" -l binr/blob/r2blob 2> /dev/null | grep -q "Requesting program interpreter"; then
		echo "WARNING: binr/blob/r2blob has a dynamic interpreter"
	fi
fi
