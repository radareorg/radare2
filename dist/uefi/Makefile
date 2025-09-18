.PHONY: all configure build clean

all: build

configure:
	cd ../.. && meson setup build-uefi --cross-file dist/uefi/cross-uefi.ini -Dstatic=true -Duse_sys_zlib=false -Duse_magic=false -Duse_openssl=false -Dexamples=false -Dtests=false -Dplugins=false

build: configure
	cd ../.. && meson compile -C build-uefi

clean:
	cd ../.. && rm -rf build-uefi