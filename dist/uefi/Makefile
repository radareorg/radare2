# builds radare2 as an EFI application (BOOTX64.EFI/BOOTAA64.EFI) using acr, clang and lld
.PHONY: all configure build link clean esp run smoke

R2DIR:=$(abspath ../..)
BUILDDIR=$(R2DIR)/build-uefi
UEFI_INCLUDE=$(R2DIR)/dist/uefi/include
CONFIG_STAMP=$(BUILDDIR)/.configured
CC=clang

EFI_ARCH?=$(shell uname -m)
ifneq ($(filter $(EFI_ARCH),x86_64 amd64),)
override EFI_ARCH:=x86_64
EFI_NAME=BOOTX64.EFI
ARCH_CFLAGS=-mno-red-zone
ARCH_LIBS=
QEMU=qemu-system-x86_64 -machine q35,accel=kvm:tcg -cpu max
QEMU_CODE?=/usr/share/OVMF/OVMF_CODE_4M.fd
QEMU_VARS?=/usr/share/OVMF/OVMF_VARS_4M.fd
else ifneq ($(filter $(EFI_ARCH),aarch64 arm64),)
override EFI_ARCH:=aarch64
EFI_NAME=BOOTAA64.EFI
# outline atomics need getauxval, x18 is reserved by the UEFI calling convention
ARCH_CFLAGS=-mno-outline-atomics -ffixed-x18
# compiler-rt provides the soft-float helpers for the 128 bit long double
ARCH_LIBS=$(shell $(CC) -rtlib=compiler-rt -print-libgcc-file-name)
QEMU=qemu-system-aarch64 -machine virt,accel=kvm:tcg -cpu max
QEMU_CODE?=/usr/share/AAVMF/AAVMF_CODE.fd
QEMU_VARS?=/usr/share/AAVMF/AAVMF_VARS.fd
else
$(error Unsupported EFI_ARCH=$(EFI_ARCH), use x86_64 or aarch64)
endif

LDS?=/usr/lib/elf_$(EFI_ARCH)_efi.lds
CRT0?=/usr/lib/crt0-efi-$(EFI_ARCH).o
AR=ar
RANLIB=ranlib
LLD?=ld.lld
OBJCOPY?=objcopy

EFI_FORMAT=--target efi-app-$(EFI_ARCH) --subsystem=10
ifeq ($(EFI_ARCH),aarch64)
# Older gnu-efi CRTs embed the PE header.
ifneq ($(findstring EFI_SUBSYSTEM,$(shell nm -u $(CRT0) 2>/dev/null)),)
EFI_LDFLAGS=--defsym=EFI_SUBSYSTEM=10
EFI_FORMAT=-O binary
endif
endif

UEFI_CFLAGS=-DR2_UEFI=1 -D__thread= -D_GNU_SOURCE -ffreestanding \
	-fno-stack-protector $(ARCH_CFLAGS) -fPIC -ffunction-sections \
	-fdata-sections -nostdlibinc -include $(UEFI_INCLUDE)/r2_uefi.h \
	-isystem /usr/include/$(EFI_ARCH)-linux-musl -I$(UEFI_INCLUDE) \
	-I/usr/include/efi -I/usr/include/efi/$(EFI_ARCH) \
	-I$(R2DIR)/libr/include -I$(R2DIR)/subprojects/sdb/include

CONFIGURE_FLAGS=--host=$(EFI_ARCH)-unknown-none --with-ostype=gnulinux \
	--with-compiler=clang --with-libr --with-static-themes \
	--disable-debugger --disable-threads --disable-loadlibs \
	--without-qjs --without-dylink --without-fork --without-ptrace-wrap \
	--without-gperf --without-zydis --without-zip --without-gpl \
	--without-jemalloc

R2LIBS=$(wildcard $(R2DIR)/libr/*/libr_*.a) \
	$(R2DIR)/subprojects/capstone-v5/libcapstone.a \
	$(R2DIR)/subprojects/sdb/src/libsdb.a \
	$(wildcard $(R2DIR)/shlr/*.a)

all: link

configure: $(CONFIG_STAMP)

$(BUILDDIR):
	mkdir -p $@

$(CONFIG_STAMP): $(R2DIR)/configure.acr \
		$(R2DIR)/dist/plugins-cfg/plugins.uefi.cfg | $(BUILDDIR)
	cd $(R2DIR) && CC=$(CC) AR=$(AR) RANLIB=$(RANLIB) \
		PKGCONFIG=/usr/bin/false CFLAGS="$(UEFI_CFLAGS)" LDFLAGS="-nostdlib" \
		./configure $(CONFIGURE_FLAGS)
	# --without-gpl replaces plugins.cfg with the nogpl set, so apply ours after
	cp $(R2DIR)/dist/plugins-cfg/plugins.uefi.cfg $(R2DIR)/plugins.cfg
	cd $(R2DIR) && ./configure-plugins $(filter-out --without-gpl,$(CONFIGURE_FLAGS))
	touch $@

build: $(CONFIG_STAMP)
	$(MAKE) -j -C $(R2DIR) libs LIBS_TARGET=sublibs WITH_LIBS=0 \
		WITH_LIBR=1 WITHOUT_PULL=1 > /dev/null

link: $(BUILDDIR)/$(EFI_NAME)

$(BUILDDIR)/main.o: main.c $(CONFIG_STAMP)
	$(CC) -c -o $@ $< $(UEFI_CFLAGS)

$(BUILDDIR)/relocate.o: relocate.c $(CONFIG_STAMP)
	$(CC) -c -o $@ $< $(UEFI_CFLAGS)

$(BUILDDIR)/uefi.o: include/uefi.c $(CONFIG_STAMP)
	$(CC) -c -o $@ $< $(UEFI_CFLAGS)

# lld does not write the implicit addends that the gnu-efi _relocate expects,
# so relocate.o provides a rela-aware replacement for it
$(BUILDDIR)/r2efi.so: build $(BUILDDIR)/main.o $(BUILDDIR)/relocate.o \
		$(BUILDDIR)/uefi.o
	$(LLD) $(EFI_LDFLAGS) -nostdlib -shared -Bsymbolic --no-undefined --gc-sections \
		-znocombreloc -T $(LDS) $(CRT0) $(BUILDDIR)/relocate.o \
		$(BUILDDIR)/main.o $(BUILDDIR)/uefi.o --start-group $(R2LIBS) \
		$(ARCH_LIBS) --end-group -o $@

$(BUILDDIR)/$(EFI_NAME): $(BUILDDIR)/r2efi.so
	$(OBJCOPY) -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym \
		-j .rel -j .rela -j '.rel.*' -j '.rela.*' -j .reloc \
		$(EFI_FORMAT) $< $@
	ls -l $@

QEMU_ARGS=-m 512M -nographic \
	-drive if=pflash,format=raw,readonly=on,file=$(QEMU_CODE) \
	-drive if=pflash,format=raw,file=$(BUILDDIR)/vars.fd \
	-drive format=raw,file=fat:rw:$(BUILDDIR)/esp
SMOKE_TIMEOUT?=300

esp: $(BUILDDIR)/$(EFI_NAME)
	mkdir -p $(BUILDDIR)/esp/EFI/BOOT
	cp -f $(BUILDDIR)/$(EFI_NAME) $(BUILDDIR)/esp/EFI/BOOT/$(EFI_NAME)
	cp -f $(QEMU_VARS) $(BUILDDIR)/vars.fd

run: esp
	$(QEMU) $(QEMU_ARGS)

smoke: esp
	@$(QEMU) $(QEMU_ARGS) < /dev/null > $(BUILDDIR)/smoke.log 2>&1 & pid=$$!; \
	i=0; while [ $$i -lt $(SMOKE_TIMEOUT) ] && kill -0 $$pid 2>/dev/null && \
		! grep -qF ']> ' $(BUILDDIR)/smoke.log; do sleep 1; i=$$((i + 1)); done; \
	kill $$pid 2>/dev/null; \
	if grep -qF ']> ' $(BUILDDIR)/smoke.log; then echo "smoke: ok"; \
	else cat $(BUILDDIR)/smoke.log; echo "smoke: no prompt after $$i s"; exit 1; fi

clean:
	$(MAKE) -C $(R2DIR) clean
	rm -rf $(BUILDDIR)
