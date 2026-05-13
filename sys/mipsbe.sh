#!/bin/sh

set -e

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)" || exit 1
TARGET="${TARGET:-mips-linux-gnu}"
CROSS="${CROSS:-${TARGET}-}"
R2R_TESTS="${R2R_TESTS:-test/db/cmd/echo test/db/cmd/cmd_print_misc test/db/cmd/cmd_hash test/db/cmd/cmd_question test/db/asm/mips_v2_64}"
R2R_TIMEOUT="${R2R_TIMEOUT:-120}"
MODE="${1:-all}"

usage() {
	echo "Usage: sys/mipsbe.sh [build|smoke|all]"
	exit 1
}

case "$MODE" in
build|smoke|all)
	;;
-h|--help)
	usage
	;;
*)
	usage
	;;
esac

find_tool() {
	if command -v "$1" >/dev/null 2>&1; then
		command -v "$1"
		return 0
	fi
	if [ -x "$1" ]; then
		echo "$1"
		return 0
	fi
	return 1
}

need_file() {
	if [ ! -e "$1" ]; then
		echo "Missing expected file: $1"
		exit 1
	fi
}

make_qemu_wrapper() {
	out="$1"
	target="$2"
	cat > "$out" <<EOF
#!/bin/sh
QEMU_LD_PREFIX="${QEMU_LD_PREFIX_DIR}"
export QEMU_LD_PREFIX
exec "$QEMU_RUN" "$target" "\$@"
EOF
	chmod +x "$out"
}

run_qemu() {
	if [ -n "$QEMU_LD_PREFIX_DIR" ]; then
		QEMU_LD_PREFIX="$QEMU_LD_PREFIX_DIR" "$QEMU_RUN" "$@"
	else
		"$QEMU_RUN" "$@"
	fi
}

run_r2r() {
	if [ -n "$QEMU_R2R" ]; then
		run_qemu "$R2R_BIN" "$@"
	else
		"$R2R_BIN" "$@"
	fi
}

cd "$ROOT" || exit 1

if [ "$MODE" != smoke ]; then
	CC="${CC:-$(find_tool "${CROSS}gcc" || true)}"
	if [ -z "$CC" ]; then
		echo "Missing required tool: ${CROSS}gcc"
		exit 1
	fi
	export CC CROSS
	export BUILD_R2R="${BUILD_R2R:-1}"
	export CONFIGURE_PLUGINS_ARGS="${CONFIGURE_PLUGINS_ARGS:---without-zydis}"
	export CFGARGS="${CFGARGS:---without-zydis}"

	sys/cross.sh "$TARGET"
fi

R2R_BIN="${ROOT}/binr/r2r/r2r"
RADARE2_BIN="${ROOT}/binr/blob/radare2"
RASM2_BIN="${ROOT}/binr/blob/rasm2"
need_file "$R2R_BIN"
need_file "$RADARE2_BIN"
need_file "$RASM2_BIN"

READELF="${READELF:-$(find_tool "${CROSS}readelf" || true)}"
if [ -n "$READELF" ]; then
	"$READELF" -h "${ROOT}/binr/blob/r2blob" | grep -q "Data:.*big endian" || {
		echo "binr/blob/r2blob is not a big-endian ELF"
		exit 1
	}
	"$READELF" -h "${ROOT}/binr/blob/r2blob" | grep -q "Machine:.*MIPS" || {
		echo "binr/blob/r2blob is not a MIPS ELF"
		exit 1
	}
fi
if [ "$MODE" = build ]; then
	exit 0
fi

QEMU_R2R=
QEMU_RUN=
QEMU_LD_PREFIX_DIR=
WRAP_DIR=
if "$R2R_BIN" -v >/dev/null 2>&1 && "$RADARE2_BIN" -v >/dev/null 2>&1; then
	R2_BIN_PATH="${ROOT}/binr/blob"
	R2R_RADARE2_BIN="$RADARE2_BIN"
	R2R_RASM2_BIN="$RASM2_BIN"
	PATH="${ROOT}/binr/blob:${PATH}"
else
	QEMU_RUN="${QEMU:-$(find_tool qemu-mips || find_tool qemu-mips-static || true)}"
	if [ -z "$QEMU_RUN" ]; then
		echo "Cannot run MIPS binaries. Install qemu-user or qemu-user-static."
		exit 1
	fi
	QEMU_LD_PREFIX_DIR="${QEMU_LD_PREFIX:-}"
	if [ -z "$QEMU_LD_PREFIX_DIR" ] && [ -d "/usr/${TARGET}" ]; then
		QEMU_LD_PREFIX_DIR="/usr/${TARGET}"
	fi
	run_qemu "$R2R_BIN" -v >/dev/null || {
		echo "Cannot run $R2R_BIN with $QEMU_RUN"
		exit 1
	}
	QEMU_R2R="$QEMU_RUN"
	WRAP_DIR="${TMPDIR:-/tmp}/r2-mipsbe.$$"
	mkdir -p "$WRAP_DIR"
	trap 'rm -rf "$WRAP_DIR"' EXIT HUP INT TERM
	for bin in r2 radare2 rabin2 rarun2 rasm2 ragg2 rahash2 rax2 ravc2 rafind2 radiff2 ; do
		if [ -e "${ROOT}/binr/blob/$bin" ]; then
			make_qemu_wrapper "$WRAP_DIR/$bin" "${ROOT}/binr/blob/$bin"
		fi
	done
	R2_BIN_PATH="$WRAP_DIR"
	R2R_RADARE2_BIN="$WRAP_DIR/radare2"
	R2R_RASM2_BIN="$WRAP_DIR/rasm2"
	PATH="${WRAP_DIR}:${PATH}"
fi

export PATH
export R2_BIN="$R2_BIN_PATH"
export R2R_RADARE2="$R2R_RADARE2_BIN"
export R2R_RASM2="$R2R_RASM2_BIN"
export R2R_OFFLINE=1
export R2R_JOBS=1

R2R_OUTPUT_ARG=
if [ -n "$R2R_OUTPUT" ]; then
	R2R_OUTPUT_ARG="-o $R2R_OUTPUT"
fi

# shellcheck disable=SC2086
run_r2r -u -L -1 -t "$R2R_TIMEOUT" $R2R_OUTPUT_ARG $R2R_TESTS
