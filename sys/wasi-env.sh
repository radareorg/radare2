export WASI_ROOT="${HOME}/Downloads/wasi"
export WASI_MAJOR=29
export WASI_VERSION=${WASI_MAJOR}.0

# Detect architecture and OS for the SDK path
WASI_ARCH=`uname -m`
WASI_OS=`uname`
case "$WASI_OS" in
linux|Linux) WASI_OS=linux ;;
darwin|Darwin) WASI_OS=macos ;;
windows|Windows) WASI_OS=mingw ;;
esac

# Try to find the SDK directory with arch-os suffix first (new format)
# If not found, fall back to the old format without suffix
if [ -d "${WASI_ROOT}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}" ]; then
	export WASI_SDK="${WASI_ROOT}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}"
else
	export WASI_SDK="${WASI_ROOT}/wasi-sdk-${WASI_VERSION}"
fi

export WASI_SYSROOT=${WASI_ROOT}/wasi-sysroot-${WASI_VERSION}
export CFLAGS="-D_WASI_EMULATED_SIGNAL -Os -flto -D__wasi__=1"
export CFLAGS="${CFLAGS} -D_WASI_EMULATED_PROCESS_CLOCKS=1"
