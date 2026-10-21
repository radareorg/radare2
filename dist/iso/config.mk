DOCKER_IMAGE ?= debian:bookworm
ISO_NAME ?= r2iso
DEBIAN_RELEASE ?= bookworm
ARCH ?= amd64
OUTPUT_DIR ?= output
WORK_DIR ?= build/live-build
ISO_PATH ?= $(OUTPUT_DIR)/$(ISO_NAME)-$(DEBIAN_RELEASE)-$(ARCH).iso

R2_GIT_URL ?= https://github.com/radareorg/radare2.git
R2_GIT_REF ?= master
R2PM_PLUGINS ?=
QEMU_MEMORY ?= 4096
