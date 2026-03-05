SHELL := /bin/sh

DOCKER_IMAGE := debian:bookworm
CONTAINER_WORKDIR := /work
CONTAINER_BUILD_ROOT := /tmp/r2iso-build
BUILD_SCRIPT := scripts/build-iso.sh

ISO_NAME := r2iso
OUTPUT_DIR := output
WORK_DIR := build/live-build
DEBIAN_RELEASE := bookworm
ARCH ?= amd64
DOCKER_PLATFORM := $(if $(filter amd64,$(ARCH)),linux/amd64,$(if $(filter arm64 aarch64,$(ARCH)),linux/arm64,linux/amd64))
ISO_PATH := $(OUTPUT_DIR)/$(ISO_NAME)-$(DEBIAN_RELEASE)-$(ARCH).iso
QEMU_MEMORY ?= 4096
QEMU_AARCH64_EFI ?=
BOOTLOADERS ?=
R2_GIT_URL := https://github.com/radareorg/radare2.git
R2_GIT_REF := master
R2PM_PLUGINS := r2dec
# R2PM_PLUGINS := r2ghidra r2frida
KEEP_R2_SOURCE := 0
KEEP_R2PM_CACHE := 0

.PHONY: all iso run run-usb clean help

all: iso

iso:
	docker run --rm --privileged \
		--platform "$(DOCKER_PLATFORM)" \
		-e ISO_NAME="$(ISO_NAME)" \
		-e OUTPUT_DIR="$(OUTPUT_DIR)" \
		-e WORK_DIR="$(WORK_DIR)" \
		-e DEBIAN_RELEASE="$(DEBIAN_RELEASE)" \
		-e ARCH="$(ARCH)" \
		-e BOOTLOADERS="$(BOOTLOADERS)" \
		-e R2_GIT_URL="$(R2_GIT_URL)" \
		-e R2_GIT_REF="$(R2_GIT_REF)" \
		-e R2PM_PLUGINS="$(R2PM_PLUGINS)" \
		-e KEEP_R2_SOURCE="$(KEEP_R2_SOURCE)" \
		-e KEEP_R2PM_CACHE="$(KEEP_R2PM_CACHE)" \
		-e SOURCE_DIR="$(CONTAINER_WORKDIR)" \
		-e BUILD_ROOT="$(CONTAINER_BUILD_ROOT)" \
		-v "$(CURDIR):$(CONTAINER_WORKDIR)" \
		-w "$(CONTAINER_WORKDIR)" \
		"$(DOCKER_IMAGE)" \
		/bin/bash "./$(BUILD_SCRIPT)"

run: iso
	@if [ "$(ARCH)" = "amd64" ]; then \
		qemu-system-x86_64 -m "$(QEMU_MEMORY)" -boot d -cdrom "$(ISO_PATH)"; \
	elif [ "$(ARCH)" = "arm64" ] || [ "$(ARCH)" = "aarch64" ]; then \
		if [ -z "$(QEMU_AARCH64_EFI)" ]; then \
			echo "Set QEMU_AARCH64_EFI to an AArch64 UEFI firmware file (example: /opt/homebrew/share/qemu/edk2-aarch64-code.fd)"; \
			exit 1; \
		fi; \
		qemu-system-aarch64 -M virt -cpu cortex-a72 -m "$(QEMU_MEMORY)" -bios "$(QEMU_AARCH64_EFI)" -cdrom "$(ISO_PATH)"; \
	else \
		echo "Unsupported ARCH='$(ARCH)'"; \
		exit 1; \
	fi

run-usb: iso
	@if [ "$(ARCH)" = "amd64" ]; then \
		qemu-system-x86_64 -m "$(QEMU_MEMORY)" -machine q35 -device qemu-xhci -drive if=none,id=usbstick,format=raw,file="$(ISO_PATH)" -device usb-storage,drive=usbstick -boot c; \
	else \
		echo "run-usb target currently supports ARCH=amd64 only"; \
		exit 1; \
	fi

clean:
	rm -rf build output

help:
	@printf '%s\n' \
		'Targets:' \
		'  make            Build Debian live ISO with radare2 and r2pm plugins' \
		'  make run        Boot generated ISO in QEMU as CD-ROM (architecture-aware)' \
		'  make run-usb    Boot generated ISO in QEMU as a raw disk (hybrid USB check)' \
		'  make clean      Remove build artifacts and generated ISOs' \
		'' \
		'Variables (override with make VAR=value):' \
		'  ISO_NAME         Output ISO basename (default: r2iso)' \
		'  DEBIAN_RELEASE   Debian suite (default: bookworm)' \
		'  ARCH             Debian architecture (default: amd64)' \
		'  DOCKER_PLATFORM  Container architecture (auto from ARCH)' \
		'  BOOTLOADERS      live-build bootloaders (auto by ARCH if empty)' \
		'  R2_GIT_REF       radare2 git ref (default: master)' \
		'  R2PM_PLUGINS     Space-separated plugins (default: r2ghidra r2frida)' \
		'  QEMU_MEMORY      RAM for make run targets in MB (default: 4096)' \
		'  QEMU_AARCH64_EFI Required only for make run ARCH=arm64' \
		'  KEEP_R2_SOURCE   Keep /usr/src/radare2 in final ISO (0|1, default: 0)' \
		'  KEEP_R2PM_CACHE  Keep r2pm cache in final ISO (0|1, default: 0)'
