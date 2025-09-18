# UEFI port

This document explains the caveats, dependncies, requirements and challenges to build radare2 for UEFI targets

* No libc (we use the `libr/include/r_util/libc.h` shim)
* Meson and make builds are supported
* Install the gnu-efi toolchain
* Disable all the features like dlopen/fork/...

## Dependencies

```bash
sudo apt install -y build-essential git python3 \
	nasm acpica-tools uuid-dev \
	gnu-efi binutils binutils-x86-64-linux-gnu \
	clang lld uuid-dev

```

## Crosscompile

```bash
meson setup build-uefi \
  --cross-file cross-uefi.ini \
  -Dstatic=true \
  -Duse_sys_zlib=false \
  -Duse_magic=false \
  -Duse_openssl=false \
  -Dexamples=false \
  -Dtests=false \
  -Dplugins=false
meson compile -C build-uefi
```

using acr:

```bash
cp -f dist/plugins/plugins.uefi.cfg plugins.cfg
./configure-plugins
CFLAGS="-ffreestanding -fno-stack-protector -fshort-wchar -mno-red-zone -fPIC" \
LDFLAGS="-nostdlib -Wl,--subsystem,10" \
./configure --host=x86_64-unknown-none --disable-all --enable-static
make -j

```

## Running

```bash
mkdir -p esp/EFI/BOOT
cp BOOTX64.EFI esp/EFI/BOOT/

qemu-system-x86_64 \
  -machine q35,accel=kvm:tcg \
  -cpu max -m 512M \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/usr/share/OVMF/OVMF_VARS.fd \
  -drive format=raw,file=fat:rw:esp
```
