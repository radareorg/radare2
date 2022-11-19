
WASI_SDK=$(HOME)/Downloads/wasi/wasi-sdk-16.0
WASI_SYSROOT=$(HOME)/Downloads/wasi/wasi-sysroot-16.0
WASI_CC="$(WASI_SDK)/bin/clang --sysroot=$(WASI_SYSROOT) -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_SIGNAL -DUSE_MMAN=0 -DHAVE_SYSTEM=0"

$(WASK_SDK):
	$(SHELL) wasi.sh
