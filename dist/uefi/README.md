# UEFI port

This directory contains everything needed to build radare2 as an EFI
application (`BOOTX64.EFI`) that runs on top of the UEFI firmware, with no
operating system and no libc underneath.

* The build uses the musl headers (`musl-dev`) plus the small compatibility
  wrappers in `dist/uefi/include`
* `dist/uefi/include/uefi.c` implements the required libc subset on top of the boot
  services: console io through the simple text protocols, the heap through
  `AllocatePool`, file io through the simple file system protocol of the
  boot volume, time through the runtime services, and plain C
  implementations for the str/mem/printf/qsort/math family
* Threads, QuickJS, fork, dynamic loading, sockets, CAN bus, ptrace, shared
  memory and the debugger are disabled
* `dist/uefi/main.c` is the `efi_main` entrypoint: it calls `r_uefi_init ()`
  to hand the boot services over to the shim and then spawns the usual r2
  core prompt loop
* `dist/uefi/relocate.c` replaces the gnu-efi `_relocate`, which relies on
  implicit addends that bfd ld writes but lld does not

## Dependencies

```bash
sudo apt install -y build-essential binutils clang lld gnu-efi musl-dev
sudo apt install -y libclang-rt-dev  # aarch64 only
```

## Building

```bash
make -C dist/uefi
```

That configures the ACR/make build, compiles the static libraries and links
`build-uefi/BOOTX64.EFI` (`BOOTAA64.EFI` on aarch64). The build is native:
`EFI_ARCH` defaults to the host and cross builds are not supported. The steps
can be run separately with `make -C dist/uefi configure build link`.

### VC4 plugin on ARM64

The ARM64 CI and release images statically include the VideoCore IV plugin
from radare2-extras through XPS. To enable it locally before configuring:

```bash
git clone https://github.com/radareorg/radare2-extras libr/xps/p/vc4
git -C libr/xps/p/vc4 checkout d5e7a28186e0cef1b698748c86bbd8aeb3c2a4de
cp -R dist/uefi/vc4/r2plugin libr/xps/p/vc4/
echo 'EXTERNAL_PLUGINS+=vc4' >> libr/xps/config.mk
make -C libr/xps
make -C dist/uefi
```

The local `vc4/r2plugin` adapter supplies the XPS metadata, the disassembler
declaration, and a regex shim using radare2's regex engine. The resulting
image includes the plugin's GPL-3.0-only code.

## Running

```bash
sudo apt install -y qemu-system-x86 ovmf               # x86_64
sudo apt install -y qemu-system-arm qemu-efi-aarch64   # aarch64
make -C dist/uefi run
```

Which boots the application in qemu with the OVMF/AAVMF firmware:

```
radare2 6.2.1 on UEFI
[0x00000000]> ?V
6.2.1 ...
[0x00000000]> wx 9090
[0x00000000]> px 16
```

`make -C dist/uefi smoke` does the same headless and fails if the prompt does
not show up.

To run it on real hardware copy `BOOTX64.EFI` or `BOOTAA64.EFI` into
`EFI/BOOT/` on a FAT32 formatted usb stick and select it from the firmware
boot menu.
