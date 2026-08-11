# radare2 + ReactOS in the browser
#
# Builds two artifacts:
#
#   reactos.qcow2  compressed qcow2 image with ReactOS installed unattended
#                  and the radare2 w32 (mingw32) build in C:\radare2
#   www/           self-contained static website that boots that image in the
#                  browser using v86 (a wasm x86 PC emulator with VGA output).
#                  The disk is fetched on demand with HTTP Range requests, so
#                  visitors only download the sectors ReactOS actually reads.
#
# Usage:
#   make check-tools     # verify host dependencies
#   make                 # build image + website (downloads the ReactOS iso)
#   make serve           # serve www/ locally on http://localhost:8080
#   make run             # boot reactos.qcow2 in native qemu
#
# Knobs:
#   make R2_W32_ZIP=/path/to/radare2-x.y.z-mingw32.zip   # reuse a w32 build
#   make DISK_MB=2048                                    # bigger disk
#   make QEMU_DISPLAY=                                   # watch the install

R2_ROOT ?= $(abspath ../..)
WORK ?= work
WWW ?= www

REACTOS_VER ?= 0.4.15
REACTOS_REL ?= release-1-gdbb43bbaeb2
REACTOS_ZIP_URL ?= https://sourceforge.net/projects/reactos/files/ReactOS/$(REACTOS_VER)/ReactOS-$(REACTOS_VER)-$(REACTOS_REL)-x86-iso.zip/download

DISK_MB ?= 1024
QEMU ?= qemu-system-i386
QEMU_MEM ?= 512
QEMU_DISPLAY ?= -display none
# the default acpi machine makes ReactOS pick the ACPI HAL, which matches
# what the browser page runs (v86 with acpi: true); installing with acpi=off
# selects the Standard PC HAL whose ps2 input does not work under v86
QEMU_MACHINE ?= pc,accel=kvm:tcg
QEMU_ARGS ?= -machine $(QEMU_MACHINE) -m $(QEMU_MEM) $(QEMU_DISPLAY) -rtc base=localtime -net none
STAGE_TIMEOUT ?= 3600

# guest memory used by the browser page; keep low so phones can run it
WEB_MEM_MB ?= 256

# extra configure flags for the w32 build; qjs is not needed to test r2
# in the reactos image and dropping it makes the binaries smaller
R2_CONFIGURE_FLAGS ?= --without-qjs

V86_VERSION ?= 0.5.424
V86_TGZ_URL ?= https://registry.npmjs.org/v86/-/v86-$(V86_VERSION).tgz
V86_BIOS_BASE ?= https://raw.githubusercontent.com/copy/v86/master/bios

CURL ?= curl -fL --retry 3
export MTOOLS_SKIP_CHECK=1

.PHONY: all image www serve run clean mrproper check-tools

all: image www

image: reactos.qcow2

www: $(WWW)/.v86.stamp $(WWW)/seabios.bin $(WWW)/vgabios.bin \
	$(WWW)/index.html $(WWW)/iso.js $(WWW)/sw.js $(WWW)/serve.py \
	$(WWW)/images/reactos.img $(WWW)/config.js

# -- ReactOS iso ---------------------------------------------------------

$(WORK)/reactos.iso:
	mkdir -p $(WORK)
	$(CURL) -o $(WORK)/reactos.zip "$(REACTOS_ZIP_URL)"
	unzip -o -d $(WORK) $(WORK)/reactos.zip
	mv $(WORK)/ReactOS-*.iso $@
	rm -f $(WORK)/reactos.zip
	touch $@

$(WORK)/unattend.inf: $(WORK)/reactos.iso
	rm -f $@.orig
	xorriso -osirrox on -indev $(WORK)/reactos.iso -extract /reactos/unattend.inf $@.orig
	chmod +w $@.orig
	sed -e 's/^UnattendSetupEnabled.*/UnattendSetupEnabled = yes/' \
	    -e 's/^FullName.*/FullName = "radare2"/' \
	    -e 's/^ComputerName.*/ComputerName = "RADARE2"/' \
	    -e 's/^FormatPartition.*/FormatPartition = 1/' \
	    -e 's/^AutoPartition.*/AutoPartition = 1/' \
	    $@.orig > $@
	printf '\r\n; add radare2 to the system PATH, keeping the defaults from hivesys.inf\r\n[Env]\r\nPath = "%%SystemRoot%%\\bin;%%SystemRoot%%\\System32;%%SystemRoot%%;%%SystemRoot%%\\System32\\Wbem;C:\\radare2"\r\n' >> $@

$(WORK)/unattend.iso: $(WORK)/unattend.inf
	cp -f $(WORK)/reactos.iso $@
	chmod +w $@
	xorriso -dev $@ -boot_image any replay -map_single $(WORK)/unattend.inf /reactos/unattend.inf

# -- unattended install --------------------------------------------------

$(WORK)/hda.qcow2:
	mkdir -p $(WORK)
	qemu-img create -f qcow2 $@ $(DISK_MB)M

# hda.qcow2 is order-only: booting the image later must not retrigger the install
$(WORK)/.stage1: $(WORK)/unattend.iso | $(WORK)/hda.qcow2
	@echo "[reactos] 1st stage (text mode) unattended install..."
	timeout $(STAGE_TIMEOUT) $(QEMU) $(QEMU_ARGS) \
		-drive file=$(WORK)/hda.qcow2,format=qcow2,if=ide \
		-cdrom $(WORK)/unattend.iso -boot d -no-reboot
	touch $@

$(WORK)/.stage2: $(WORK)/.stage1
	@echo "[reactos] 2nd stage (gui) unattended install..."
	timeout $(STAGE_TIMEOUT) $(QEMU) $(QEMU_ARGS) \
		-drive file=$(WORK)/hda.qcow2,format=qcow2,if=ide \
		-cdrom $(WORK)/unattend.iso -boot c -no-reboot
	touch $@

# -- radare2 w32 build ---------------------------------------------------

ifneq ($(R2_W32_ZIP),)
R2ZIP := $(R2_W32_ZIP)
else
R2ZIP := $(lastword $(sort $(wildcard $(R2_ROOT)/radare2-*-mingw32.zip)))
endif

$(WORK)/r2dist/.stamp:
	mkdir -p $(WORK)
	@if [ -z "$(R2ZIP)" ]; then \
		echo "[r2] no radare2-*-mingw32.zip found, building it (this reconfigures the source tree for mingw!)"; \
		( cd $(R2_ROOT) && sys/mingw32.sh $(R2_CONFIGURE_FLAGS) ); \
	fi
	rm -rf $(WORK)/r2dist $(WORK)/r2x
	mkdir -p $(WORK)/r2x
	Z="$(R2ZIP)"; [ -n "$$Z" ] || Z="$$(ls -t $(R2_ROOT)/radare2-*-mingw32.zip | head -n1)"; \
	echo "[r2] using $$Z"; \
	unzip -o -q "$$Z" -d $(WORK)/r2x
	D="$$(find $(WORK)/r2x -maxdepth 1 -mindepth 1 -type d | head -n1)"; \
	if [ -n "$$D" ]; then mv "$$D" $(WORK)/r2dist; else mv $(WORK)/r2x $(WORK)/r2dist; fi
	rm -rf $(WORK)/r2x
	touch $@

$(WORK)/r2.cmd:
	mkdir -p $(WORK)
	printf '@echo off\r\nset "PATH=%%PATH%%;C:\\radare2"\r\n"C:\\radare2\\radare2.exe" %%*\r\n' > $@

# -- inject radare2 into the installed image -----------------------------

$(WORK)/reactos.raw: $(WORK)/.stage2 $(WORK)/r2dist/.stamp $(WORK)/r2.cmd
	qemu-img convert -O raw $(WORK)/hda.qcow2 $@.tmp
	OFF="$$(sfdisk -d $@.tmp 2>/dev/null | sed -n 's/.*start= *\([0-9][0-9]*\).*/\1/p' | head -n1)"; \
	[ -n "$$OFF" ] || { echo "cannot find first partition offset"; exit 1; }; \
	OFF=$$((OFF * 512)); \
	echo "[inject] copying radare2 into C:/radare2 (partition offset $$OFF)"; \
	mmd -i $@.tmp@@$$OFF ::/radare2 2>/dev/null || true; \
	mcopy -o -s -i $@.tmp@@$$OFF $(WORK)/r2dist/* ::/radare2/; \
	mcopy -o -i $@.tmp@@$$OFF $(WORK)/r2.cmd ::/ReactOS/system32/r2.cmd
	mv $@.tmp $@

reactos.qcow2: $(WORK)/reactos.raw
	qemu-img convert -c -O qcow2 $< $@
	qemu-img info $@

# -- website (v86) -------------------------------------------------------

$(WORK)/v86.tgz:
	mkdir -p $(WORK)
	$(CURL) -o $@ $(V86_TGZ_URL)

$(WWW)/.v86.stamp: $(WORK)/v86.tgz
	mkdir -p $(WWW)
	tar -xzf $< -C $(WORK) package/build/libv86.js package/build/v86.wasm
	cp -f $(WORK)/package/build/libv86.js $(WWW)/libv86.js
	cp -f $(WORK)/package/build/v86.wasm $(WWW)/v86.wasm
	touch $@

$(WWW)/seabios.bin:
	mkdir -p $(WWW)
	$(CURL) -o $@ $(V86_BIOS_BASE)/seabios.bin

$(WWW)/vgabios.bin:
	mkdir -p $(WWW)
	$(CURL) -o $@ $(V86_BIOS_BASE)/vgabios.bin

$(WWW)/index.html: web/index.html
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/iso.js: web/iso.js
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/sw.js: web/sw.js
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/serve.py: web/serve.py
	mkdir -p $(WWW)
	cp -f $< $@

$(WWW)/images/reactos.img: $(WORK)/reactos.raw
	mkdir -p $(WWW)/images
	cp --sparse=always -f $< $@

$(WWW)/config.js: $(WWW)/images/reactos.img
	SIZE="$$(stat -c %s $(WWW)/images/reactos.img)"; \
	VER="$$(md5sum $(WWW)/images/reactos.img | cut -c1-8)"; \
	printf 'window.VM_CONFIG = {\n  version: "%s",\n  memory_mb: %s,\n  hda: { url: "images/reactos.img", size: %s }\n};\n' \
		"$$VER" "$(WEB_MEM_MB)" "$$SIZE" > $@

# -- convenience ---------------------------------------------------------

serve: www
	cd $(WWW) && python3 serve.py 8080

run: reactos.qcow2
	$(QEMU) -machine $(QEMU_MACHINE) -m $(QEMU_MEM) -rtc base=localtime -net none \
		-drive file=reactos.qcow2,format=qcow2,if=ide

check-tools:
	@ok=1; for t in curl unzip xorriso qemu-img $(QEMU) sfdisk mcopy mmd python3 md5sum; do \
		command -v $$t >/dev/null 2>&1 || { echo "missing: $$t"; ok=0; }; \
	done; \
	command -v mcopy >/dev/null 2>&1 || echo "  (mcopy/mmd come from the 'mtools' package)"; \
	[ "$$ok" = 1 ] && echo "all tools found" || exit 1

clean:
	rm -rf $(WORK)

mrproper: clean
	rm -rf $(WWW) reactos.qcow2
