export WASI_ROOT="${HOME}/Downloads/wasi"
export WASI_MAJOR=29
export WASI_VERSION=${WASI_MAJOR}.0
export WASI_SDK=${WASI_ROOT}/wasi-sdk-${WASI_VERSION}
export WASI_SYSROOT=${WASI_ROOT}/wasi-sysroot-${WASI_VERSION}
export CFLAGS="-D_WASI_EMULATED_SIGNAL -Os -flto -D__wasi__=1"
export CFLAGS="${CFLAGS} -D_WASI_EMULATED_PROCESS_CLOCKS=1"
