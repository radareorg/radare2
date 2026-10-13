SHELL := /bin/sh
include config.mk

.PHONY: all iso run clean help

all: iso

iso:
	docker run --rm --privileged \
		-v "$(CURDIR):/src" -w /src \
		-e ISO_NAME="$(ISO_NAME)" \
		-e DEBIAN_RELEASE="$(DEBIAN_RELEASE)" \
		-e ARCH="$(ARCH)" \
		-e OUTPUT_DIR="$(OUTPUT_DIR)" \
		-e WORK_DIR="$(WORK_DIR)" \
		-e R2_GIT_URL="$(R2_GIT_URL)" \
		-e R2_GIT_REF="$(R2_GIT_REF)" \
		-e R2PM_PLUGINS="$(R2PM_PLUGINS)" \
		"$(DOCKER_IMAGE)" /bin/bash ./scripts/build-iso.sh

run:
	qemu-system-x86_64 -m "$(QEMU_MEMORY)" -boot d -cdrom "$(ISO_PATH)"

clean:
	rm -rf build output

help:
	@echo "make [iso|run|clean]"
