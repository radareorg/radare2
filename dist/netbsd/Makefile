# radare2 + NetBSD in the browser
#
# Builds two artifacts:
#
#   netbsd.qcow2   compressed qcow2 image with a minimal NetBSD/i386 installed
#                  unattended (via anita) and radare2 cross-compiled from this
#                  tree into /usr/local
#   www/           self-contained static website that boots that image in the
#                  browser using v86, reusing the runtime from ../reactos.
#                  The disk is fetched on demand with HTTP Range requests.
#
# Usage:
#   make check-tools     # verify host dependencies
#   make                 # build image + website
#   make r2              # only cross-compile radare2 for NetBSD (work/r2.tgz)
#   make serve           # serve www/ locally on http://localhost:8080
#   make run             # boot netbsd.qcow2 in native qemu
#
# Knobs:
#   make NETBSD_VER=10.0                          # other NetBSD release
#   make R2_NETBSD_TGZ=/path/to/r2.tgz            # reuse a NetBSD r2 build
#   make DISK_MB=2048                             # bigger disk
#   make ANITA_ACCEL=                             # no kvm (slow install)

R2_ROOT ?= $(abspath ../..)
REACTOS ?= ../reactos
WORK ?= work
WWW ?= www

# changing the version needs a `make clean` first (sysroot, r2 build and
# installed image are all version-specific)
NETBSD_VER ?= 11.0
NETBSD_ARCH ?= i386
MIRROR ?= https://cdn.netbsd.org/pub/NetBSD
# anita wants the trailing slash
DIST_URL ?= $(MIRROR)/NetBSD-$(NETBSD_VER)/$(NETBSD_ARCH)/
SETS_URL ?= $(DIST_URL)binary/sets

DISK_MB ?= 1024
INSTALL_MEM_MB ?= 512
ANITA_SETS ?= kern-GENERIC,modules,base,etc,rescue
# MBR + disklabel is the best-tested BIOS boot path in v86; sysinst would
# otherwise pick GPT
ANITA_PART ?= MBR
ANITA_URL ?= http://www.gson.org/netbsd/anita/download/anita-2.18.tar.gz
ANITA_ACCEL ?= -accel kvm -accel tcg
RUN_TIMEOUT ?= 1800
VENV = $(WORK)/venv
ANITA = $(VENV)/bin/anita

QEMU ?= qemu-system-i386
QEMU_MEM ?= 256

# guest memory used by the browser page; keep low so phones can run it
WEB_MEM_MB ?= 256
# v86's acpi emulation is incomplete; NetBSD boots fine on the non-acpi path
WEB_ACPI ?= false
# no single quotes in either of these, they are spliced into shell
# single-quoted strings
WEB_CD_NOTE ?= run `mount /mnt` in the guest
WEB_HINT ?= Boots into an auto-logged-in <b>root</b> shell — try <b>r2 /bin/ls</b>; radare2 lives in <b>/usr/local</b>. Disk data is streamed on demand; the first boot downloads a few tens of MB. On phones use the <b>Keyboard</b> button to type. Upload or drop files, then run <b>mount /mnt</b> in the guest to read them (<b>umount /mnt</b> before uploading again).

# cross toolchain: clang targeting netbsd against a sysroot made from the
# base+comp sets, linking with lld
CLANG ?= clang
TRIPLE ?= i386-unknown-netbsd$(NETBSD_VER)
SYSROOT = $(abspath $(WORK)/sysroot)
CC_WRAP = $(abspath $(WORK)/bin/netbsd-clang)
R2_CONFIGURE_FLAGS ?= --without-qjs
JOBS ?= $(shell nproc 2> /dev/null || echo 4)

# custom kernel: GENERIC does not survive v86 (see guest/V86.conf and the
# README); built with NetBSD's own cross build.sh from the source sets
KERNEL_CONF ?= V86
SRC_URL ?= $(MIRROR)/NetBSD-$(NETBSD_VER)/source/sets
SRC_SETS ?= src syssrc gnusrc sharesrc
KSRC = $(WORK)/ksrc
KERNEL_BUILT = $(KSRC)/obj/sys/arch/$(NETBSD_ARCH)/compile/$(KERNEL_CONF)/netbsd

V86_VERSION ?= 0.5.424
V86_TGZ_URL ?= https://registry.npmjs.org/v86/-/v86-$(V86_VERSION).tgz
V86_BIOS_BASE ?= https://raw.githubusercontent.com/copy/v86/master/bios

CURL ?= curl -fL --retry 3

.PHONY: all image www r2 kernel sysroot serve run webtest clean mrproper check-tools FORCE

FORCE:

all: image www

image: netbsd.qcow2

r2: $(WORK)/r2.tgz

kernel: $(WORK)/netbsd.v86

sysroot: $(WORK)/sysroot/.stamp

www: $(WWW)/.v86.stamp $(WWW)/seabios.bin $(WWW)/vgabios.bin \
	$(WWW)/index.html $(WWW)/iso.js $(WWW)/sw.js $(WWW)/serve.py \
	$(WWW)/images/netbsd.img $(WWW)/config.js

# -- anita (unattended NetBSD installer driving qemu) --------------------

$(ANITA):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip -q install pexpect $(ANITA_URL)

# -- sysroot from the NetBSD sets ----------------------------------------

$(WORK)/sets/%.tgz:
	mkdir -p $(WORK)/sets
	$(CURL) -o $@.tmp $(SETS_URL)/$*.tgz
	mv $@.tmp $@

# built in a temp dir and moved in place so an interrupted extraction can
# never leave a half-populated sysroot behind
$(WORK)/sysroot/.stamp: $(WORK)/sets/base.tgz $(WORK)/sets/comp.tgz
	rm -rf $(WORK)/sysroot $(WORK)/sysroot.tmp
	mkdir -p $(WORK)/sysroot.tmp
	tar -xzf $(WORK)/sets/base.tgz -C $(WORK)/sysroot.tmp ./lib ./usr/lib
	tar -xzf $(WORK)/sets/comp.tgz -C $(WORK)/sysroot.tmp ./usr/include ./usr/lib
	# the machine -> i386 symlink is made by postinstall, not shipped in the set
	ln -sf i386 $(WORK)/sysroot.tmp/usr/include/machine
	mv $(WORK)/sysroot.tmp $(WORK)/sysroot
	touch $@

# --no-rosegment and -z norelro make lld emit the classic two PT_LOAD
# layout; netbsd's ld.elf_so refuses to map libraries with more segments
# ("wrong number of segments (4 != 2)")
$(WORK)/bin/netbsd-clang: Makefile
	mkdir -p $(WORK)/bin
	printf '#!/bin/sh\nexec $(CLANG) --target=$(TRIPLE) --sysroot=$(SYSROOT) -fuse-ld=lld -Wl,--no-rosegment -Wl,-z,norelro "$$@"\n' > $@
	chmod +x $@

# -- radare2 cross build -------------------------------------------------

ifneq ($(R2_NETBSD_TGZ),)
$(WORK)/r2.tgz: $(R2_NETBSD_TGZ)
	mkdir -p $(WORK)
	cp -f $< $@
else
# the wrapper is order-only: regenerating it (any Makefile edit) must not
# retrigger this whole build
$(WORK)/r2.tgz: $(WORK)/sysroot/.stamp | $(WORK)/bin/netbsd-clang
	@echo "[r2] cross-building radare2 for $(TRIPLE) (this reconfigures the source tree!)"
	-$(MAKE) -C $(R2_ROOT) clean > /dev/null 2>&1
	cd $(R2_ROOT) && cp -f dist/plugins-cfg/plugins.def.cfg plugins.cfg
	cd $(R2_ROOT) && CC=$(CC_WRAP) HOST_CC=cc ./configure \
		--host=i386-unknown-netbsd --with-ostype=bsd --with-compiler=clang \
		--with-rpath --prefix=/usr/local $(R2_CONFIGURE_FLAGS)
	$(MAKE) -C $(R2_ROOT) -j$(JOBS) CC=$(CC_WRAP) HOST_CC=cc
	rm -rf $(WORK)/r2root
	$(MAKE) -C $(R2_ROOT) install DESTDIR=$(abspath $(WORK)/r2root)
	@S="$$(command -v llvm-strip || ls /usr/bin/llvm-strip-* 2> /dev/null | head -n1)"; \
	if [ -n "$$S" ]; then \
		echo "[r2] stripping with $$S"; \
		find $(WORK)/r2root/usr/local/bin $(WORK)/r2root/usr/local/lib \
			-type f \( -name '*.so*' -o -perm -111 \) \
			-exec "$$S" --strip-all {} \; 2> /dev/null || true; \
	fi
	# root ownership and no group-write: the guest extracts over /, netbsd
	# tar as root restores ownership and modes, and pam refuses logins when
	# path components like /usr are user-owned or group-writable
	chmod -R go-w $(WORK)/r2root
	tar -czf $@ --owner=0 --group=0 --numeric-owner -C $(WORK)/r2root .
endif

# -- unattended install + inject -----------------------------------------

$(WORK)/anita/wd0.img: | $(ANITA)
	@echo "[netbsd] unattended install via anita (takes a few minutes with kvm)..."
	$(ANITA) --workdir $(WORK)/anita --disk-size $(DISK_MB)M \
		--memory-size $(INSTALL_MEM_MB)M --sets $(ANITA_SETS) \
		--partitioning-scheme $(ANITA_PART) \
		--vmm-args "$(ANITA_ACCEL)" install $(DIST_URL)

# -- custom kernel -------------------------------------------------------

$(KSRC)/.stamp:
	mkdir -p $(KSRC)
	for s in $(SRC_SETS); do \
		$(CURL) -o $(KSRC)/$$s.tgz $(SRC_URL)/$$s.tgz || exit 1; \
	done
	for s in $(SRC_SETS); do \
		tar -xzf $(KSRC)/$$s.tgz -C $(KSRC) || exit 1; \
	done
	for p in $(abspath $(wildcard guest/*.patch)); do \
		echo "[kernel] applying $$p"; \
		(cd $(KSRC)/usr/src && patch -p1 < $$p) || exit 1; \
	done
	touch $@

# netbsd's build.sh needs its own cross toolchain (gcc + binutils); this is
# the slow part, the kernel itself rebuilds in a couple of minutes
$(KSRC)/tools/.stamp: $(KSRC)/.stamp
	cd $(KSRC)/usr/src && ./build.sh -m $(NETBSD_ARCH) -U -j$(JOBS) \
		-T $(abspath $(KSRC)/tools) -O $(abspath $(KSRC)/obj) tools
	touch $@

$(WORK)/netbsd.v86: guest/$(KERNEL_CONF).conf $(KSRC)/tools/.stamp
	cp -f guest/$(KERNEL_CONF).conf \
		$(KSRC)/usr/src/sys/arch/$(NETBSD_ARCH)/conf/$(KERNEL_CONF)
	cd $(KSRC)/usr/src && ./build.sh -m $(NETBSD_ARCH) -U -j$(JOBS) \
		-T $(abspath $(KSRC)/tools) -O $(abspath $(KSRC)/obj) \
		kernel=$(KERNEL_CONF)
	cp -f $(KERNEL_BUILT) $@

# which timecounter the guest pins. clockinterrupt just counts ticks so it
# cannot go backwards, and sleeps still time out to the millisecond; i8254
# has finer resolution but samples v86's jittery browser-derived clock and
# then trips "timecounter went backwards"
GUEST_TIMECOUNTER ?= clockinterrupt

# rewritten whenever its content would change, so that switching
# GUEST_TIMECOUNTER takes effect without touching guest/install.sh
$(WORK)/install.sh: guest/install.sh Makefile FORCE
	@mkdir -p $(WORK)
	@sed -e 's/@TIMECOUNTER@/$(GUEST_TIMECOUNTER)/' $< > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; echo "[guest] install.sh updated"; fi

$(WORK)/r2.iso: $(WORK)/r2.tgz $(WORK)/netbsd.v86 $(WORK)/install.sh
	xorriso -as mkisofs -quiet -r -o $@ -graft-points \
		r2.tgz=$(WORK)/r2.tgz netbsd.v86=$(WORK)/netbsd.v86 \
		install.sh=$(WORK)/install.sh

# wd0.img is order-only: injecting modifies it, a normal dep would loop.
# NOTE: install.sh switches the boot console to VGA (consdev=pc), and anita
# drives the serial console — so this must be the LAST anita operation on the
# image; to run anita again, reinstall first (rm work/anita/wd0.img)
$(WORK)/.inject: $(WORK)/r2.iso | $(WORK)/anita/wd0.img $(ANITA)
	@echo "[netbsd] injecting radare2 into the image..."
	$(ANITA) --workdir $(WORK)/anita --persist --run-timeout $(RUN_TIMEOUT) \
		--vmm-args "$(ANITA_ACCEL) -cdrom $(abspath $(WORK)/r2.iso)" \
		--run "mount_cd9660 /dev/cd0a /mnt && sh /mnt/install.sh && umount /mnt" \
		boot $(DIST_URL)
	touch $@

$(WORK)/netbsd.raw: $(WORK)/.inject
	qemu-img convert -f raw -O raw $(WORK)/anita/wd0.img $@.tmp
	mv $@.tmp $@

# boot the injected image once, natively: rc's fsck repairs the superblocks
# and marks the file system clean, and the one-shot in /etc/rc.local powers
# the machine off again. without this every browser boot repeats the repair,
# because writes in the browser are volatile
$(WORK)/.settle: $(WORK)/netbsd.raw
	@echo "[netbsd] settling the file system (boots once and powers off)..."
	timeout $(RUN_TIMEOUT) $(QEMU) -machine pc,accel=kvm:tcg -m $(QEMU_MEM) \
		-net none -display none -no-reboot \
		-drive file=$(WORK)/netbsd.raw,format=raw,if=ide
	touch $@

netbsd.qcow2: $(WORK)/.settle
	qemu-img convert -c -O qcow2 $(WORK)/netbsd.raw $@
	qemu-img info $@

# -- website: reuse the v86 runtime from ../reactos ----------------------

$(WWW)/.v86.stamp:
	mkdir -p $(WWW)
	@if [ -f $(REACTOS)/www/libv86.js ] && [ -f $(REACTOS)/www/v86.wasm ]; then \
		echo "[v86] reusing $(REACTOS)/www"; \
		cp -f $(REACTOS)/www/libv86.js $(REACTOS)/www/v86.wasm $(WWW)/; \
	else \
		mkdir -p $(WORK); \
		$(CURL) -o $(WORK)/v86.tgz $(V86_TGZ_URL); \
		tar -xzf $(WORK)/v86.tgz -C $(WORK) package/build/libv86.js package/build/v86.wasm; \
		cp -f $(WORK)/package/build/libv86.js $(WWW)/libv86.js; \
		cp -f $(WORK)/package/build/v86.wasm $(WWW)/v86.wasm; \
	fi
	touch $@

$(WWW)/seabios.bin $(WWW)/vgabios.bin:
	mkdir -p $(WWW)
	@if [ -f $(REACTOS)/www/$(@F) ]; then \
		cp -f $(REACTOS)/www/$(@F) $@; \
	else \
		$(CURL) -o $@ $(V86_BIOS_BASE)/$(@F); \
	fi

$(WWW)/index.html: $(REACTOS)/web/index.html
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/iso.js: $(REACTOS)/web/iso.js
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/sw.js: $(REACTOS)/web/sw.js
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/serve.py: $(REACTOS)/web/serve.py
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/images/netbsd.img: $(WORK)/.settle
	mkdir -p $(WWW)/images
	cp --sparse=always -f $(WORK)/netbsd.raw $@

$(WWW)/config.js: $(WWW)/images/netbsd.img
	SIZE="$$(stat -c %s $(WWW)/images/netbsd.img)"; \
	VER="$$(md5sum $(WWW)/images/netbsd.img | cut -c1-8)"; \
	{ printf 'window.VM_CONFIG = {\n'; \
	  printf '  version: "%s",\n' "$$VER"; \
	  printf '  title: "radare2 on NetBSD",\n'; \
	  printf '  memory_mb: %s,\n' "$(WEB_MEM_MB)"; \
	  printf '  acpi: %s,\n' "$(WEB_ACPI)"; \
	  printf '  hda: { url: "images/netbsd.img", size: %s },\n' "$$SIZE"; \
	  printf '  cd_note: "%s",\n' '$(WEB_CD_NOTE)'; \
	  printf '  hint: "%s"\n' '$(WEB_HINT)'; \
	  printf '};\n'; \
	} > $@

# -- convenience ---------------------------------------------------------

serve: www
	cd $(WWW) && python3 serve.py 8080

# boot the www image headless in v86 itself (via node) and dump the text
# screen; reproduces browser-side boot problems without a browser.
# WEBTEST_TYPE='cmd' runs a command once the shell prompt shows up
webtest: www
	node webtest.js

run: netbsd.qcow2
	$(QEMU) -machine pc,accel=kvm:tcg -m $(QEMU_MEM) -net none \
		-drive file=netbsd.qcow2,format=qcow2,if=ide

check-tools:
	@ok=1; for t in curl tar xorriso qemu-img $(QEMU) python3 md5sum $(CLANG) ld.lld cc c++ node; do \
		command -v $$t > /dev/null 2>&1 || { echo "missing: $$t"; ok=0; }; \
	done; \
	python3 -c 'import venv' 2> /dev/null || { echo "missing: python3-venv"; ok=0; }; \
	[ -w /dev/kvm ] || echo "  (no /dev/kvm: the unattended install will be slow)"; \
	[ "$$ok" = 1 ] && echo "all tools found" || exit 1

clean:
	rm -rf $(WORK)

mrproper: clean
	rm -rf $(WWW) netbsd.qcow2
