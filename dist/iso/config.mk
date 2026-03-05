DOCKER_IMAGE ?= debian:bookworm
CONTAINER_WORKDIR ?= /work
CONTAINER_BUILD_ROOT ?= /tmp/r2iso-build
BUILD_SCRIPT ?= scripts/build-iso.sh

ISO_NAME ?= r2iso
OUTPUT_DIR ?= output
WORK_DIR ?= build/live-build
DEBIAN_RELEASE ?= bookworm
ARCH ?= amd64
DOCKER_PLATFORM ?= $(if $(filter amd64,$(ARCH)),linux/amd64,$(if $(filter arm64 aarch64,$(ARCH)),linux/arm64,linux/amd64))
ISO_PATH ?= $(OUTPUT_DIR)/$(ISO_NAME)-$(DEBIAN_RELEASE)-$(ARCH).iso
QEMU_MEMORY ?= 4096
QEMU_AARCH64_EFI ?=
BOOTLOADERS ?=

R2_GIT_URL ?= https://github.com/radareorg/radare2.git
R2_GIT_REF ?= master
R2PM_PLUGINS ?= r2dec
# R2PM_PLUGINS ?= r2ghidra r2frida
KEEP_R2_SOURCE ?= 0
KEEP_R2PM_CACHE ?= 0
ROOTFS_DIR ?= rootfs
ISO_MOTD ?= Welcome to r2iso
# ROOT_PASSWORD_MODE: empty | password | locked
ROOT_PASSWORD_MODE ?= empty
ROOT_PASSWORD ?= radare2

HOST_BUILD_PACKAGES ?= ca-certificates curl debootstrap git live-build mtools squashfs-tools syslinux-common xorriso

ISO_CHROOT_PACKAGES ?= ca-certificates curl file git gcc meson ninja-build vim libcapstone-dev liblz4-dev libmagic-dev libssl-dev libuv1-dev libxxhash-dev libzstd-dev libzip-dev make pkg-config python3 wget zlib1g-dev build-essential

ISO_CHROOT_PURGE_PACKAGES ?= build-essential libcapstone-dev liblz4-dev libmagic-dev libssl-dev libuv1-dev libxxhash-dev libzstd-dev libzip-dev zlib1g-dev
