# R2ISO

Build a small Debian live ISO with the latest `radare2` from git and optional `r2pm` plugins.

## Usage

```sh
make
```

All defaults are centralized in `dist/iso/config.mk`.
Files under `dist/iso/rootfs/` are copied directly into the ISO root filesystem.

Default build architecture is `amd64` (x86_64).

To build ARM64 explicitly:

```sh
make ARCH=arm64
```

The ISO will be written to `output/` as:

```text
<ISO_NAME>-<DEBIAN_RELEASE>-<ARCH>.iso
```

## Main Makefile Variables

Override variables like:

```sh
make R2_GIT_REF=master R2PM_PLUGINS="r2ghidra r2frida"
```

- `ISO_NAME`: output ISO basename (`r2iso`)
- `DEBIAN_RELEASE`: Debian suite (`bookworm`)
- `ARCH`: Debian architecture (`amd64` by default, use `arm64` if needed)
- `BOOTLOADERS`: override live-build bootloaders (default auto: `syslinux,grub-efi` for amd64, `grub-efi` for arm64)
- `R2_GIT_URL`: radare2 git URL
- `R2_GIT_REF`: git branch/tag/commit to build (`master`)
- `R2PM_PLUGINS`: space-separated plugin list
- `KEEP_R2_SOURCE`: keep `/usr/src/radare2` in final ISO (`0`/`1`)
- `KEEP_R2PM_CACHE`: keep r2pm cache in final ISO (`0`/`1`)
- `ROOTFS_DIR`: overlay directory copied into the final rootfs (`rootfs`)
- `BOOT_BRANDING_DIR`: bootloader branding assets directory (`assets/boot`)
- `ISO_MOTD`: text written to `/etc/motd`
- `ROOT_PASSWORD_MODE`: root password policy (`empty`, `password`, or `locked`)
- `ROOT_PASSWORD`: root password when `ROOT_PASSWORD_MODE=password`
- `HOST_BUILD_PACKAGES`: packages installed in the builder container
- `ISO_CHROOT_PACKAGES`: packages installed in final ISO rootfs
- `ISO_CHROOT_PURGE_PACKAGES`: packages purged after building radare2

Default `ISO_CHROOT_PACKAGES` includes the tools needed by `r2pm` plugin builds:
`gcc`, `meson`, `ninja` (`ninja-build` package), `git`, and `vim`.

Default overlay includes `rootfs/etc/r2ascii.txt` and `rootfs/etc/profile.d/r2ascii.sh`
to display the ASCII banner from `doc/r2ascii.txt` before the shell prompt.

Default login is `root` / `radare2` (`ROOT_PASSWORD_MODE=password`).

## QEMU Testing

For x86_64 ISO (default):

```sh
make run
```

This uses `qemu-system-x86_64` with `-cdrom`.

Important:
- `qemu-system-x86_64 -hda output/r2iso-bookworm-arm64.iso` is not correct for your arm64 ISO.
- `-hda` is for disk images, not ISO CD media.
- `qemu-system-x86_64` cannot boot an `arm64` ISO.

If you build `ARCH=arm64`, use:

```sh
make run ARCH=arm64 QEMU_AARCH64_EFI=/path/to/edk2-aarch64-code.fd
```

You can also test hybrid/USB-style boot for x86_64 with:

```sh
make run-usb
```

## Flashing To USB

The generated image is `iso-hybrid`, so it is directly writable to a pendrive.

Example (`/dev/sdX` is your USB disk, not a partition):

```sh
sudo dd if=output/r2iso-bookworm-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync
sync
```

## Cleaning

```sh
make clean
```

Removes generated build workspace and output artifacts.
