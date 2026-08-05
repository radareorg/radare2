# radare2 + JSLinux (TinyEMU) running riscv64 Linux in the browser
#
# Builds a self-contained static website (www/) that boots a riscv64
# Linux (Fabrice Bellard's JSLinux, MIT-licensed TinyEMU compiled to
# WASM) with a size-optimized static radare2 injected into the rootfs.
#
# radare2 is cross-compiled as a single static binary (r2blob, all the
# r2 tools in one executable, busybox-style) using a musl riscv64
# toolchain from toolchains.bootlin.com, with the minimal plugin set
# from dist/plugins-cfg/plugins.jslinux.cfg: no debugger, no qjs, only
# ELF and the riscv arch. Shipping r2 into the guest image is just
# copying that one binary plus symlinks.
#
# Usage:
#   make check-tools     # verify host dependencies
#   make                 # build r2blob + rootfs + website
#   make r2              # only cross-compile r2blob (work/r2blob)
#   make serve           # serve www/ on http://localhost:8080
#   make run             # boot the image in a natively built temu
#
# Knobs:
#   make ROOT_MB=96                        # bigger guest disk
#   make R2BLOB=/path/to/r2blob            # reuse a prebuilt rv64 blob
#   make TC_VER=2024.05-1                  # other bootlin toolchain

R2_ROOT ?= $(abspath ../..)
WORK ?= work
WWW ?= www

# changing versions needs a `make clean` first
JSLINUX_VER ?= 2019-12-21
JSLINUX_URL ?= https://bellard.org/tinyemu/jslinux-$(JSLINUX_VER).tar.gz
TINYEMU_URL ?= https://bellard.org/tinyemu/tinyemu-$(JSLINUX_VER).tar.gz

# musl so -static produces a truly self-contained binary; the guest
# kernel is 4.15 which the riscv64 musl port targets as its minimum
TC_VER ?= 2025.08-1
TC_NAME ?= riscv64-lp64d--musl--stable-$(TC_VER)
TC_URL ?= https://toolchains.bootlin.com/downloads/releases/toolchains/riscv64-lp64d/tarballs/$(TC_NAME).tar.xz
TCDIR = $(abspath $(WORK)/$(TC_NAME))
CC_WRAP = $(abspath $(WORK)/bin/rv64-musl-gcc)

# guest ext2 image size; the pristine jslinux rootfs is 4MB with ~1.4MB
# free, so it must grow to fit r2blob
ROOT_MB ?= 64
# jslinux streams the disk on demand in chunks of this size (KB)
BLK_KB ?= 256

R2_CFLAGS ?= -Oz -ffunction-sections -fdata-sections
# --with-libr builds the static libr_*.a archives the blob links against;
# --with-static-themes compiles the color themes into the binary since the
# guest image ships no r2 share directory
R2_CONFIGURE_FLAGS ?= --disable-debugger --without-ptrace-wrap --without-qjs \
	--without-capstone --without-zydis --without-gpl --without-dylink \
	--disable-loadlibs --with-checks-level=0 --with-libr --with-static-themes
R2_LINKS = r2 radare2 rabin2 rasm2 rax2 rahash2 rafind2 radiff2 ragg2 rarun2 ravc2 rafs2
JOBS ?= $(shell nproc 2> /dev/null || echo 4)

JSL = $(WORK)/jslinux-$(JSLINUX_VER)
RUNTIME_FILES = jslinux.js term.js style.css riscvemu64.js \
	riscvemu64-wasm.js riscvemu64-wasm.wasm bbl64.bin kernel-riscv64.bin

CURL ?= curl -fL --retry 3

HOST_OS := $(shell uname -s)
USE_DOCKER ?= $(if $(filter Darwin,$(HOST_OS)),1,0)
DOCKER ?= docker
DOCKER_IMAGE ?= radare2-jslinux-builder
# Bootlin's prebuilt cross toolchain is an x86-64 Linux binary.
DOCKER_PLATFORM ?= linux/amd64
DOCKER_TARGET ?= all

.PHONY: all www r2 image docker docker-build serve run clean mrproper check-tools

ifeq ($(USE_DOCKER),1)
all: docker

r2 image www:
	$(MAKE) docker DOCKER_TARGET=$@
else
all: www

r2: $(WORK)/r2blob

.PHONY: dist

include ../../config-user.mk
D=r2-$(VERSION)-jslinux-www
dist:
	cp -rf $(WWW) $(D)
	rm -f $(D).zip
	zip -r $(D).zip $(D)

image: $(WORK)/root-r2.bin

www: $(WWW)/.runtime.stamp $(WWW)/index.html $(WWW)/root-riscv64.cfg \
	$(WWW)/serve.py $(WWW)/root-r2/blk.txt $(WWW)/netfs/head
endif

# -- container build ------------------------------------------------------

docker: docker-build
	$(DOCKER) run --rm \
		--platform "$(DOCKER_PLATFORM)" \
		--user "$$(id -u):$$(id -g)" \
		--volume "$(R2_ROOT):$(R2_ROOT)" \
		--workdir "$(CURDIR)" \
		"$(DOCKER_IMAGE)" \
		make USE_DOCKER=0 \
			R2_ROOT="$(R2_ROOT)" WORK="$(WORK)" WWW="$(WWW)" \
			JSLINUX_VER="$(JSLINUX_VER)" JSLINUX_URL="$(JSLINUX_URL)" \
			TINYEMU_URL="$(TINYEMU_URL)" TC_VER="$(TC_VER)" \
			TC_NAME="$(TC_NAME)" TC_URL="$(TC_URL)" \
			ROOT_MB="$(ROOT_MB)" BLK_KB="$(BLK_KB)" JOBS="$(JOBS)" \
			R2_CFLAGS="$(R2_CFLAGS)" \
			R2_CONFIGURE_FLAGS="$(R2_CONFIGURE_FLAGS)" \
			R2BLOB="$(R2BLOB)" CURL="$(CURL)" "$(DOCKER_TARGET)"

docker-build:
	$(DOCKER) build --platform "$(DOCKER_PLATFORM)" \
		-t "$(DOCKER_IMAGE)" .

# -- cross toolchain -------------------------------------------------------

$(WORK)/dl/$(TC_NAME).tar.xz:
	mkdir -p $(WORK)/dl
	$(CURL) -o $@.tmp $(TC_URL)
	mv $@.tmp $@

$(TCDIR)/.stamp: $(WORK)/dl/$(TC_NAME).tar.xz
	tar -xJf $< -C $(WORK)
	touch $@

# bootlin ships both the short riscv64-linux-* and the full
# riscv64-buildroot-linux-musl-* names; pick whichever exists
$(CC_WRAP): $(TCDIR)/.stamp
	mkdir -p $(WORK)/bin
	@CCBIN="$$(ls $(TCDIR)/bin/riscv64-linux-gcc 2> /dev/null || \
		ls $(TCDIR)/bin/riscv64-*-musl-gcc 2> /dev/null | head -n1)"; \
	[ -n "$$CCBIN" ] || { echo "no riscv64 gcc in $(TCDIR)/bin"; exit 1; }; \
	printf '#!/bin/sh\nexec %s "$$@"\n' "$$CCBIN" > $@
	chmod +x $@

# -- radare2 cross build ---------------------------------------------------

ifneq ($(R2BLOB),)
$(WORK)/r2blob: $(R2BLOB)
	mkdir -p $(WORK)
	cp -f $< $@
else
# the wrapper is order-only: regenerating it must not retrigger this build
$(WORK)/r2blob: | $(CC_WRAP)
	@echo "[r2] cross-building static r2blob for riscv64 (this reconfigures the source tree!)"
	-$(MAKE) -C $(R2_ROOT) clean > /dev/null 2>&1
	cd $(R2_ROOT) && cp -f dist/plugins-cfg/plugins.jslinux.cfg plugins.cfg
	cd $(R2_ROOT) && ./configure-plugins
	cd $(R2_ROOT) && CC=$(CC_WRAP) HOST_CC=cc CFLAGS="$(R2_CFLAGS)" ./configure \
		--host=riscv64-unknown-linux-musl --with-ostype=gnulinux \
		--prefix=/usr $(R2_CONFIGURE_FLAGS)
	$(MAKE) -C $(R2_ROOT) -j$(JOBS) CC=$(CC_WRAP) HOST_CC=cc
	cd $(R2_ROOT)/binr/blob && rm -f r2blob && \
		LDFLAGS="-static -Wl,--gc-sections" $(MAKE) CC=$(CC_WRAP) build
	@STRIP="$$(ls $(TCDIR)/bin/riscv64-linux-strip 2> /dev/null || \
		ls $(TCDIR)/bin/riscv64-*-strip 2> /dev/null | head -n1)"; \
	[ -n "$$STRIP" ] && "$$STRIP" --strip-all $(R2_ROOT)/binr/blob/r2blob || true
	mkdir -p $(WORK)
	cp -f $(R2_ROOT)/binr/blob/r2blob $@
	@ls -l $@
endif

# -- guest rootfs: grow the pristine image and inject r2blob ---------------

$(JSL)/.stamp:
	mkdir -p $(WORK)/dl
	$(CURL) -o $(WORK)/dl/jslinux.tar.gz.tmp $(JSLINUX_URL)
	mv $(WORK)/dl/jslinux.tar.gz.tmp $(WORK)/dl/jslinux.tar.gz
	tar -xzf $(WORK)/dl/jslinux.tar.gz -C $(WORK)
	touch $@

# guest/ is a rootfs overlay: every file in it lands at the same path in
# the image; setuprootfs.sh does the whole grow+inject dance with debugfs
GUEST_FILES = $(shell find guest -type f | sort)

$(WORK)/root-r2.bin: $(WORK)/r2blob $(JSL)/.stamp $(GUEST_FILES) setuprootfs.sh
	./setuprootfs.sh $(JSL)/root-riscv64.bin $@ $(WORK)/r2blob $(ROOT_MB) "$(R2_LINKS)"

# split into fixed-size chunks so the browser only downloads the blocks
# it actually reads (same format as TinyEMU's splitimg tool)
$(WWW)/root-r2/blk.txt: $(WORK)/root-r2.bin
	rm -rf $(WWW)/root-r2
	mkdir -p $(WWW)/root-r2
	split -b $(BLK_KB)k -a 9 -d $< $(WWW)/root-r2/blk
	for B in $(WWW)/root-r2/blk*; do mv "$$B" "$$B.bin"; done
	N="$$(ls $(WWW)/root-r2/blk*.bin | wc -l)"; \
	printf '{\n  block_size: %s,\n  n_block: %s,\n}\n' "$(BLK_KB)" "$$N" > $@

# -- website ---------------------------------------------------------------

# the cols/rows/font_size defaults become overridable from index.html so
# the terminal geometry can adapt to the viewport (phones)
$(WWW)/.runtime.stamp: $(JSL)/.stamp web/term-colors.patch
	mkdir -p $(WWW)/images
	cd $(JSL) && cp -f $(RUNTIME_FILES) $(abspath $(WWW))/
	# upstream term.js only knows 16 colors: teach it 256/truecolor SGR
	# sequences and brighten the base palette (see web/term-colors.patch)
	patch --batch --no-backup-if-mismatch $(WWW)/term.js web/term-colors.patch
	sed \
		-e 's/(params\["cols"\] | 0) || 80/(params["cols"] | 0) || window.R2_COLS || 80/' \
		-e 's/(params\["rows"\] | 0) || 30/(params["rows"] | 0) || window.R2_ROWS || 30/' \
		-e 's/(params\["font_size"\] | 0) || 15/(params["font_size"] | 0) || window.R2_FONT || 15/' \
		$(WWW)/jslinux.js > $(WWW)/jslinux.js.tmp
	mv $(WWW)/jslinux.js.tmp $(WWW)/jslinux.js
	cp -f $(JSL)/images/*.png $(WWW)/images/
	touch $@

# empty in-memory 9p filesystem manifest: mounting it in the guest (see
# guest/etc/profile) is what makes browser file uploads work — TinyEMU's
# fs_import_file drops uploads into this fs under /tmp
$(WWW)/netfs/head: $(WORK)/tinyemu/build_filelist
	rm -rf $(WORK)/netfsroot $(WWW)/netfs
	mkdir -p $(WORK)/netfsroot/tmp
	$(WORK)/tinyemu/build_filelist $(WORK)/netfsroot $(WWW)/netfs

$(WWW)/index.html: web/index.html
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/root-riscv64.cfg: web/root-riscv64.cfg
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/serve.py: web/serve.py
	mkdir -p $(WWW)
	cp -f $< $@

# -- convenience -----------------------------------------------------------

serve: www
	cd $(WWW) && python3 serve.py 8080

# boot the same rootfs in a natively compiled TinyEMU; reproduces guest
# problems (and lets you play with the image) without a browser
$(WORK)/tinyemu/.src.stamp:
	mkdir -p $(WORK)/dl
	$(CURL) -o $(WORK)/dl/tinyemu.tar.gz $(TINYEMU_URL)
	rm -rf $(WORK)/tinyemu $(WORK)/tinyemu-$(JSLINUX_VER)
	tar -xzf $(WORK)/dl/tinyemu.tar.gz -C $(WORK)
	mv $(WORK)/tinyemu-$(JSLINUX_VER) $(WORK)/tinyemu
	touch $@

$(WORK)/tinyemu/temu: $(WORK)/tinyemu/.src.stamp
	$(MAKE) -C $(WORK)/tinyemu CONFIG_X86EMU= CONFIG_SDL= CONFIG_FS_NET= temu

$(WORK)/tinyemu/build_filelist: $(WORK)/tinyemu/.src.stamp
	$(MAKE) -C $(WORK)/tinyemu CONFIG_X86EMU= CONFIG_SDL= CONFIG_FS_NET= build_filelist

# fs0 shares work/netfsroot with the native guest so the same 9p mount
# from guest/etc/profile works here too (uploads equivalent: drop files there)
$(WORK)/temu.cfg: $(WORK)/root-r2.bin $(JSL)/.stamp
	mkdir -p $(WORK)/netfsroot/tmp
	{ printf '{\n  version: 1,\n  machine: "riscv64",\n  memory_size: 256,\n'; \
	  printf '  bios: "%s",\n' "$(abspath $(JSL)/bbl64.bin)"; \
	  printf '  kernel: "%s",\n' "$(abspath $(JSL)/kernel-riscv64.bin)"; \
	  printf '  cmdline: "console=hvc0 root=/dev/vda rw",\n'; \
	  printf '  drive0: { file: "%s" },\n' "$(abspath $(WORK)/root-r2.bin)"; \
	  printf '  fs0: { file: "%s", tag: "r2fs" },\n}\n' "$(abspath $(WORK)/netfsroot)"; \
	} > $@

run: $(WORK)/tinyemu/temu $(WORK)/temu.cfg
	$(WORK)/tinyemu/temu $(WORK)/temu.cfg

check-tools:
ifeq ($(USE_DOCKER),1)
	@command -v $(DOCKER) > /dev/null 2>&1 || { echo "missing: $(DOCKER)"; exit 1; }
	@$(DOCKER) version > /dev/null
	@echo "docker is available"
else
	@ok=1; for t in curl file tar wget xz split truncate e2fsck resize2fs \
			debugfs python3 cc gperf patch; do \
		command -v $$t > /dev/null 2>&1 || { echo "missing: $$t"; ok=0; }; \
	done; \
	[ "$$ok" = 1 ] && echo "all tools found" || exit 1
endif

clean:
	rm -rf $(WORK)

mrproper: clean
	rm -rf $(WWW)
