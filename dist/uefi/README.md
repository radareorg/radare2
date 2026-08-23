# UEFI port

This directory contains everything needed to build radare2 as an EFI
application (`BOOTX64.EFI`) that runs on top of the UEFI firmware, with no
operating system and no libc underneath.

* No libc headers are shipped: the cross build compiles against the musl
  headers (`musl-dev`), keeping the compiler builtin ones via `-nostdlibinc`
* `libr/util/uefi.c` implements the libc natively on top of the boot
  services: console io through the simple text protocols, the heap through
  `AllocatePool`, file io through the simple file system protocol of the
  boot volume, time through the runtime services, and plain C
  implementations for the str/mem/printf/qsort/math family
* Features that make no sense on firmware are disabled with `R2_UEFI` ifdefs
  or build options: threads, fork, dynamic loading, sockets, CAN bus, ptrace,
  shared memory and the debugger
* `dist/uefi/main.c` is the `efi_main` entrypoint: it calls `r_uefi_init ()`
  to hand the boot services over to the shim and then spawns the usual r2
  core prompt loop
* `dist/uefi/relocate.c` replaces the gnu-efi `_relocate`, which relies on
  implicit addends that bfd ld writes but lld does not

## Dependencies

```bash
sudo apt install -y build-essential git python3 clang lld gnu-efi musl-dev
pip install meson ninja
```

## Building

```bash
make -C dist/uefi
```

That configures meson with `dist/uefi/cross-uefi.ini`, compiles all the
libraries and links `build-uefi/BOOTX64.EFI`. The steps can be run separately
with `make -C dist/uefi configure build link`.

## Running

```bash
sudo apt install -y qemu-system-x86 ovmf
make -C dist/uefi run
```

Which boots the application in qemu with the OVMF firmware:

```
radare2 6.2.1 on UEFI
[0x00000000]> ?V
6.2.1 ...
[0x00000000]> wx 9090
[0x00000000]> px 16
```

To run it on real hardware copy `BOOTX64.EFI` into `EFI/BOOT/` on a FAT32
formatted usb stick and select it from the firmware boot menu.
