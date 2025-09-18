.PHONY: all configure build

CFLAGS += -DR2_UEFI=1
export CFLAGS

all: build

configure:
	 rm -rf ../../build-uefi
	 cd ../.. && meson setup build-uefi --cross-file dist/uefi/cross-uefi.ini -Dstatic_runtime=true -Duse_sys_zlib=false -Duse_sys_magic=false -Duse_sys_openssl=false -Denable_tests=false -Dplugins= -Duse_fork=false -Duse_dylink=false -Ddebugger=false

build: configure
	 cd ../.. && meson compile -C build-uefi

clean:
	 cd ../.. && rm -rf build-uefi
