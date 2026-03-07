export WASI_ROOT="${WASI_ROOT:-${HOME}/Downloads/wasi}"
export WASI_MAJOR="${WASI_MAJOR:-29}"
export WASI_VERSION="${WASI_VERSION:-${WASI_MAJOR}.0}"

# Detect architecture and OS for the SDK path
export WASI_ARCH=`uname -m`
export WASI_OS=`uname`
case "$WASI_OS" in
linux|Linux) WASI_OS=linux ;;
darwin|Darwin) WASI_OS=macos ;;
windows|Windows) WASI_OS=mingw ;;
esac
export WASI_OS

export WASI_DOWNLOAD_DIR="${WASI_DOWNLOAD_DIR:-${WASI_ROOT}/distfiles}"
export WASI_SDK_URL="${WASI_SDK_URL:-https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_MAJOR}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}.tar.gz}"
export WASI_SYSROOT_URL="${WASI_SYSROOT_URL:-https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_MAJOR}/wasi-sysroot-${WASI_VERSION}.tar.gz}"
export WASI_SDK_ARCHIVE="${WASI_SDK_ARCHIVE:-${WASI_DOWNLOAD_DIR}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}.tar.gz}"
export WASI_SYSROOT_ARCHIVE="${WASI_SYSROOT_ARCHIVE:-${WASI_DOWNLOAD_DIR}/wasi-sysroot-${WASI_VERSION}.tar.gz}"

# Try to find the SDK directory with arch-os suffix first (new format)
# If not found, fall back to the old format without suffix
if [ -d "${WASI_ROOT}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}" ]; then
	export WASI_SDK="${WASI_ROOT}/wasi-sdk-${WASI_VERSION}-${WASI_ARCH}-${WASI_OS}"
else
	export WASI_SDK="${WASI_SDK:-${WASI_ROOT}/wasi-sdk-${WASI_VERSION}}"
fi

export WASI_SYSROOT="${WASI_SYSROOT:-${WASI_ROOT}/wasi-sysroot-${WASI_VERSION}}"
export CFLAGS="-D_WASI_EMULATED_SIGNAL -Os -flto -D__wasi__=1"
export CFLAGS="${CFLAGS} -D_WASI_EMULATED_PROCESS_CLOCKS=1"
