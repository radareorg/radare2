# radare2 + JSLinux (TinyEMU) running riscv64 Linux in the browser
#
# Builds a self-contained static website (www/) that boots a riscv64
# Linux (Fabrice Bellard's JSLinux, MIT-licensed TinyEMU compiled to
# WASM) with size-optimized static radare2 and TinyCC injected into the
# rootfs. TinyCC can be omitted with SHIP_TCC=0.
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
#   make tcc             # only cross-compile/stage TinyCC
#   make serve           # serve www/ on http://localhost:8080
#   make run             # boot the image in a natively built temu
#
# Knobs:
#   make ROOT_MB=96                        # bigger guest disk
#   make R2BLOB=/path/to/r2blob            # reuse a prebuilt rv64 blob
#   make TC_VER=2024.05-1                  # other bootlin toolchain
#   make SHIP_TCC=0                         # omit TinyCC from the rootfs

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

# TinyCC's default branch is "mob". This pins its HEAD as of 2026-08-08;
# changing the commit changes both the download and build directories.
SHIP_TCC ?= 1
TCC_COMMIT ?= 64552b3faa39ee7948a9ea21bfcc11045b90c70d
TCC_URL ?= https://github.com/TinyCC/tinycc/archive/$(TCC_COMMIT).tar.gz
TCC_SRC = $(WORK)/tinycc-$(TCC_COMMIT)
TCC_BUILD = $(WORK)/tinycc-build-$(TCC_COMMIT)
TCC_ROOT = $(WORK)/tcc-root-$(TCC_COMMIT)
TCC_STAMP = $(WORK)/.tcc-root-$(TCC_COMMIT).stamp
TCC_RUNNER ?= qemu-riscv64
TCC_CFLAGS ?= -Oz -ffunction-sections -fdata-sections \
	-fno-asynchronous-unwind-tables -fno-unwind-tables
TCC_LDFLAGS ?= -static -Wl,--gc-sections
# Keep the complete libc/POSIX headers, but leave out the large Linux device
# UAPI trees. TinyCC's own headers remain under /usr/lib/tcc/include.
TCC_MUSL_HEADER_DIRS = arpa bits net netinet netpacket sys
TCC_MUSL_STUB_LIBS = libcrypt.a libdl.a libm.a libpthread.a libresolv.a \
	librt.a libutil.a libxnet.a

ifeq ($(filter $(SHIP_TCC),0 1),)
$(error SHIP_TCC must be 0 or 1)
endif

TCC_ROOTFS_DEPS =
TCC_ROOTFS_ARGS =
TCC_HOST_TOOLS =
ifeq ($(SHIP_TCC),1)
TCC_ROOTFS_DEPS += $(TCC_STAMP)
TCC_ROOTFS_ARGS += "$(abspath $(TCC_ROOT))"
TCC_HOST_TOOLS += $(firstword $(TCC_RUNNER))
endif

# guest ext2 image size; the pristine jslinux rootfs is 4MB with ~1.4MB
# free, so it must grow to fit r2blob
ROOT_MB ?= 16
# jslinux streams the disk on demand in chunks of this size (KB)
BLK_KB ?= 256

R2_CFLAGS ?= -Oz -ffunction-sections -fdata-sections
# --with-libr builds the static libr_*.a archives the blob links against;
# --with-static-themes compiles the color themes into the binary since the
# guest image ships no r2 share directory.
#
# only `make libs LIBS_TARGET=sublibs WITH_LIBS=0` is run in the r2 tree:
# the 16 binr/ programs, the merged libr.a/libr.so and every shared library
# are pure waste here, since the blob is one static binary symlinked to all
# the tool names inside the image (busybox-style).
R2_CONFIGURE_FLAGS ?= --without-qjs \
	--without-capstone --without-zydis --without-gpl \
	--with-checks-level=0 --with-libr --with-static-themes
R2_LINKS = r2 radare2 rabin2 rasm2 rax2 rahash2 rafind2 radiff2 ragg2 rarun2 ravc2 rafs2
JOBS ?= $(shell nproc 2> /dev/null || echo 4)

JSL = $(WORK)/jslinux-$(JSLINUX_VER)
RUNTIME_FILES = jslinux.js term.js style.css riscvemu64.js \
	riscvemu64-wasm.js riscvemu64-wasm.wasm bbl64.bin kernel-riscv64.bin
OFFLINE_STATIC_FILES = $(RUNTIME_FILES) index.html favicon.ico \
	apple-touch-icon.png manifest.webmanifest offline-files.js \
	root-riscv64.cfg service-worker.js
OFFLINE_DYNAMIC_DIRS = images root-r2 netfs
SERVICE_WORKER_TEMPLATE = $(abspath web/service-worker.js)
APP_ICON = $(R2_ROOT)/dist/macos/pkg/Resources/r2logo.png

CURL ?= curl -fL --retry 3

HOST_OS := $(shell uname -s)
USE_DOCKER ?= $(if $(filter Darwin,$(HOST_OS)),1,0)
DOCKER ?= docker
DOCKER_IMAGE ?= radare2-jslinux-builder
# Bootlin's prebuilt cross toolchain is an x86-64 Linux binary.
DOCKER_PLATFORM ?= linux/amd64
DOCKER_TARGET ?= all

.PHONY: all www r2 tcc image docker docker-build serve run clean mrproper check-tools

ifeq ($(USE_DOCKER),1)
all: docker

r2 tcc image www:
	$(MAKE) docker DOCKER_TARGET=$@
else
all: www

r2: $(WORK)/r2blob

tcc: $(TCC_STAMP)

image: $(WORK)/root-r2.bin

www: $(WWW)/.runtime.stamp $(WWW)/index.html $(WWW)/favicon.ico \
	$(WWW)/apple-touch-icon.png $(WWW)/manifest.webmanifest \
	$(WWW)/root-riscv64.cfg $(WWW)/serve.py $(WWW)/root-r2/blk.txt \
	$(WWW)/netfs/head $(WWW)/offline-files.js $(WWW)/service-worker.js
endif

.PHONY: dist

include ../../config-user.mk
D=r2-$(VERSION)-jslinux-www
dist: www
	rm -rf $(D) $(D).zip
	mkdir -p $(D)
	cp -rf $(WWW)/. $(D)
	rm -f $(D)/.*.stamp
	zip -r $(D).zip $(D)
	rm -rf $(D)
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
			SHIP_TCC="$(SHIP_TCC)" TCC_COMMIT="$(TCC_COMMIT)" \
			TCC_URL="$(TCC_URL)" TCC_RUNNER="$(TCC_RUNNER)" \
			TCC_CFLAGS="$(TCC_CFLAGS)" \
			TCC_LDFLAGS="$(TCC_LDFLAGS)" \
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

# -- TinyCC cross build ---------------------------------------------------

$(WORK)/dl/tinycc-$(TCC_COMMIT).tar.gz:
	mkdir -p $(WORK)/dl
	$(CURL) -o $@.tmp $(TCC_URL)
	mv $@.tmp $@

$(TCC_SRC)/.stamp: $(WORK)/dl/tinycc-$(TCC_COMMIT).tar.gz
	rm -rf $(TCC_SRC)
	tar -xzf $< -C $(WORK)
	touch $@

# Build a static compiler so it does not depend on the old glibc in the
# guest. Programs produced by tcc use the much smaller shared musl runtime.
# libtcc1 is built by the new riscv64 tcc under user-mode emulation. This is
# necessary because its cache-flush runtime uses a TinyCC RISC-V intrinsic
# which GCC does not implement. CONFIG_predefs=no avoids needing a generated
# target c2str helper before tcc itself exists.
$(TCC_STAMP): $(TCC_SRC)/.stamp $(CC_WRAP) Makefile
	rm -rf $(TCC_BUILD) $(TCC_ROOT)
	mkdir -p $(TCC_BUILD)
	@AR="$$(ls $(TCDIR)/bin/riscv64-linux-ar 2> /dev/null || \
		ls $(TCDIR)/bin/riscv64-*-ar 2> /dev/null | head -n1)"; \
	[ -n "$$AR" ] || { echo "no riscv64 ar in $(TCDIR)/bin"; exit 1; }; \
	cd $(TCC_BUILD) && $(abspath $(TCC_SRC))/configure \
		--prefix=/usr --tccdir=/usr/lib/tcc --cpu=riscv64 \
		--targetos=Linux --triplet=riscv64-buildroot-linux-musl \
		--cc=$(CC_WRAP) --ar="$$AR" --config-musl \
		--config-backtrace=no --config-bcheck=no --config-predefs=no \
		--sysincludepaths='{B}/include:/usr/include' \
		--libpaths='{B}:/lib:/usr/lib' --crtprefix='{B}' \
		--elfinterp=/lib/ld-musl-riscv64.so.1 \
		--extra-cflags='$(TCC_CFLAGS)' \
		--extra-ldflags='$(TCC_LDFLAGS)'
	$(MAKE) -C $(TCC_BUILD) -j$(JOBS) GITHASH=no ONE_SOURCE=yes tcc
	$(TCC_RUNNER) $(TCC_BUILD)/tcc -v
	@SYSROOT="$$($(CC_WRAP) -print-sysroot)"; \
	$(MAKE) -C $(TCC_BUILD) -j$(JOBS) GITHASH=no ONE_SOURCE=yes \
		XCC="$(TCC_RUNNER) $(abspath $(TCC_BUILD))/tcc -nostdinc \
		-I$(abspath $(TCC_SRC))/include -I$$SYSROOT/usr/include" \
		XAR="$(TCC_RUNNER) $(abspath $(TCC_BUILD))/tcc -ar" libtcc1.a
	@SYSROOT="$$($(CC_WRAP) -print-sysroot)"; \
	STRIP="$$(ls $(TCDIR)/bin/riscv64-linux-strip 2> /dev/null || \
		ls $(TCDIR)/bin/riscv64-*-strip 2> /dev/null | head -n1)"; \
	[ -d "$$SYSROOT/usr/include" ] || { echo "bad musl sysroot: $$SYSROOT"; exit 1; }; \
	[ -n "$$STRIP" ] || { echo "no riscv64 strip in $(TCDIR)/bin"; exit 1; }; \
	mkdir -p $(TCC_ROOT)/usr/bin $(TCC_ROOT)/usr/include \
		$(TCC_ROOT)/usr/lib/tcc/include $(TCC_ROOT)/lib \
		$(TCC_ROOT)/usr/share/licenses/tinycc; \
	install -m 755 $(TCC_BUILD)/tcc $(TCC_ROOT)/usr/bin/tcc; \
	install -m 644 $(TCC_BUILD)/libtcc1.a $(TCC_ROOT)/usr/lib/tcc/libtcc1.a; \
	install -m 644 $(TCC_BUILD)/runmain.o $(TCC_ROOT)/usr/lib/tcc/runmain.o; \
	install -m 644 $(TCC_SRC)/include/*.h $(TCC_SRC)/tcclib.h \
		$(TCC_ROOT)/usr/lib/tcc/include; \
	install -m 644 "$$SYSROOT"/usr/include/*.h $(TCC_ROOT)/usr/include; \
	for D in $(TCC_MUSL_HEADER_DIRS); do \
		cp -a "$$SYSROOT/usr/include/$$D" $(TCC_ROOT)/usr/include/; \
	done; \
	install -m 644 "$$SYSROOT"/lib/crt1.o "$$SYSROOT"/lib/crti.o \
		"$$SYSROOT"/lib/crtn.o $(TCC_ROOT)/usr/lib/tcc; \
	for L in $(TCC_MUSL_STUB_LIBS); do \
		install -m 644 "$$SYSROOT/lib/$$L" $(TCC_ROOT)/usr/lib/tcc; \
	done; \
	install -m 755 "$$SYSROOT"/lib/libc.so $(TCC_ROOT)/lib/libc.so; \
	ln -s libc.so $(TCC_ROOT)/lib/ld-musl-riscv64.so.1; \
	install -m 644 $(TCC_SRC)/COPYING \
		$(TCC_ROOT)/usr/share/licenses/tinycc/COPYING; \
	"$$STRIP" --strip-all $(TCC_ROOT)/usr/bin/tcc; \
	"$$STRIP" --strip-unneeded $(TCC_ROOT)/lib/libc.so; \
	"$$STRIP" --strip-debug $(TCC_ROOT)/usr/lib/tcc/libtcc1.a \
		$(TCC_ROOT)/usr/lib/tcc/runmain.o $(TCC_ROOT)/usr/lib/tcc/crt1.o \
		$(TCC_ROOT)/usr/lib/tcc/crti.o $(TCC_ROOT)/usr/lib/tcc/crtn.o; \
	$(TCC_RUNNER) $(TCC_ROOT)/usr/bin/tcc -nostdinc \
		-B$(abspath $(TCC_ROOT))/usr/lib/tcc \
		-I$(abspath $(TCC_ROOT))/usr/lib/tcc/include \
		-I$(abspath $(TCC_ROOT))/usr/include \
		-L$(abspath $(TCC_ROOT))/lib $(TCC_SRC)/examples/ex1.c \
		-lm -ldl -lpthread \
		-o $(TCC_BUILD)/tcc-smoke; \
	$(TCC_RUNNER) -L $(abspath $(TCC_ROOT)) $(TCC_BUILD)/tcc-smoke; \
	touch $@
	@du -sh $(TCC_ROOT)

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
	$(MAKE) -C $(R2_ROOT) libs -j$(JOBS) CC=$(CC_WRAP) HOST_CC=cc \
		LIBS_TARGET=sublibs WITH_LIBS=0 WITH_LIBR=1
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

.PHONY: rootfs-config-force
ROOTFS_CONFIG = $(WORK)/.rootfs-config
$(ROOTFS_CONFIG): rootfs-config-force
	@mkdir -p $(WORK)
	@printf 'SHIP_TCC=%s\nROOT_MB=%s\n' "$(SHIP_TCC)" "$(ROOT_MB)" > $@.tmp; \
	if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv -f $@.tmp $@; fi

$(WORK)/root-r2.bin: $(WORK)/r2blob $(JSL)/.stamp $(GUEST_FILES) \
		setuprootfs.sh $(ROOTFS_CONFIG) $(TCC_ROOTFS_DEPS)
	./setuprootfs.sh $(JSL)/root-riscv64.bin $@ $(WORK)/r2blob \
		$(ROOT_MB) "$(R2_LINKS)" $(TCC_ROOTFS_ARGS)

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
$(WWW)/.runtime.stamp: $(JSL)/.stamp Makefile web/term-colors.patch web/term-wheel.patch
	mkdir -p $(WWW)/images
	cd $(JSL) && cp -f $(RUNTIME_FILES) $(abspath $(WWW))/
	rm -f $(WWW)/term.js.rej
	# Keep the wheel hunk separate: GNU patch cannot apply it after the
	# line-number shifts introduced by the color patch, while BSD patch can.
	patch --batch --no-backup-if-mismatch $(WWW)/term.js web/term-wheel.patch
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

$(WWW)/favicon.ico: web/favicon.ico
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/apple-touch-icon.png: $(APP_ICON)
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/manifest.webmanifest: web/manifest.webmanifest
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/root-riscv64.cfg: web/root-riscv64.cfg
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/serve.py: web/serve.py
	mkdir -p $(WWW)
	cp -f $< $@

# Generate one versioned file list for both the page's foreground downloader
# and the service worker. The two generated filenames cannot hash themselves,
# so include the Makefile and worker template in their cache version instead.
$(WWW)/offline-files.js: Makefile web/service-worker.js $(WWW)/.runtime.stamp \
		$(WWW)/index.html $(WWW)/favicon.ico $(WWW)/apple-touch-icon.png \
		$(WWW)/manifest.webmanifest $(WWW)/root-riscv64.cfg \
		$(WWW)/root-r2/blk.txt $(WWW)/netfs/head
	@set -e; \
	cd "$(WWW)"; \
	{ for F in $(OFFLINE_STATIC_FILES); do printf '%s\n' "$$F"; done; \
		find $(OFFLINE_DYNAMIC_DIRS) -type f -print; \
	} | LC_ALL=C sort -u > .offline-files.tmp; \
	VERSION="$$( \
		{ while IFS= read -r F; do \
			if [ "$$F" = offline-files.js ] || [ "$$F" = service-worker.js ]; then \
				continue; \
			fi; \
			printf '%s ' "$$F"; cksum < "$$F"; \
		  done \
			< .offline-files.tmp; \
			cksum < "$(abspath Makefile)"; \
			cksum < "$(SERVICE_WORKER_TEMPLATE)"; \
		} | cksum | awk '{print $$1}' \
	)"; \
	{ printf '/* Generated by dist/jslinux/Makefile. */\n'; \
		printf '"use strict";\n\n'; \
		printf 'const R2_CACHE_NAME = "jslr2-offline-%s";\n' "$$VERSION"; \
		printf 'const R2_OFFLINE_FILES = [\n\t"./",\n'; \
		while IFS= read -r F; do printf '\t"%s",\n' "$$F"; done \
			< .offline-files.tmp; \
		printf '];\n'; \
	} > offline-files.js.tmp; \
	mv offline-files.js.tmp offline-files.js; \
	rm -f .offline-files.tmp

# Embedding the same generated metadata changes the worker bytes whenever the
# bundle changes, which reliably triggers the service worker update algorithm.
$(WWW)/service-worker.js: web/service-worker.js $(WWW)/offline-files.js
	@{ cat $(WWW)/offline-files.js; printf '\n'; cat $<; } > $@.tmp
	@mv $@.tmp $@

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
			debugfs python3 cc gperf patch $(TCC_HOST_TOOLS); do \
		command -v $$t > /dev/null 2>&1 || { echo "missing: $$t"; ok=0; }; \
	done; \
	[ "$$ok" = 1 ] && echo "all tools found" || exit 1
endif

clean:
	rm -rf $(WORK)

mrproper: clean
	rm -rf $(WWW)
