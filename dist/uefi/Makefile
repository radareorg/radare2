# builds radare2 as an EFI application (BOOTX64.EFI) using acr, clang and lld

.PHONY: all configure build link clean run

R2DIR:=$(abspath ../..)
BUILDDIR=$(R2DIR)/build-uefi
UEFI_INCLUDE=$(R2DIR)/dist/uefi/include
CONFIG_STAMP=$(BUILDDIR)/.configured
LDS?=/usr/lib/elf_x86_64_efi.lds
CRT0?=/usr/lib/crt0-efi-x86_64.o
CC=clang
AR=ar
RANLIB=ranlib
LLD?=ld.lld
OBJCOPY?=objcopy

UEFI_CFLAGS=-DR2_UEFI=1 -D__thread= -D_GNU_SOURCE -ffreestanding \
	-fno-stack-protector -mno-red-zone -fPIC -ffunction-sections \
	-fdata-sections -nostdlibinc -include $(UEFI_INCLUDE)/r2_uefi.h \
	-isystem /usr/include/x86_64-linux-musl -I$(UEFI_INCLUDE) \
	-I/usr/include/efi -I/usr/include/efi/x86_64 \
	-I$(R2DIR)/libr/include -I$(R2DIR)/subprojects/sdb/include

CONFIGURE_FLAGS=--host=x86_64-unknown-none --with-ostype=gnulinux \
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
	cp $(R2DIR)/dist/plugins-cfg/plugins.uefi.cfg $(R2DIR)/plugins.cfg
	cd $(R2DIR) && ./configure-plugins
	cd $(R2DIR) && CC=$(CC) AR=$(AR) RANLIB=$(RANLIB) \
		PKGCONFIG=/usr/bin/false CFLAGS="$(UEFI_CFLAGS)" LDFLAGS="-nostdlib" \
		./configure $(CONFIGURE_FLAGS)
	touch $@

build: $(CONFIG_STAMP)
	$(MAKE) -j -C $(R2DIR) libs LIBS_TARGET=sublibs WITH_LIBS=0 \
		WITH_LIBR=1 WITHOUT_PULL=1 > /dev/null

link: $(BUILDDIR)/BOOTX64.EFI

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
	$(LLD) -nostdlib -shared -Bsymbolic --no-undefined --gc-sections \
		-znocombreloc -T $(LDS) $(CRT0) $(BUILDDIR)/relocate.o \
		$(BUILDDIR)/main.o $(BUILDDIR)/uefi.o --start-group $(R2LIBS) \
		--end-group -o $@

$(BUILDDIR)/BOOTX64.EFI: $(BUILDDIR)/r2efi.so
	$(OBJCOPY) -j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym \
		-j .rel -j .rela -j '.rel.*' -j '.rela.*' -j .reloc \
		--target efi-app-x86_64 --subsystem=10 $< $@
	ls -l $@

run: $(BUILDDIR)/BOOTX64.EFI
	mkdir -p $(BUILDDIR)/esp/EFI/BOOT
	cp -f $(BUILDDIR)/BOOTX64.EFI $(BUILDDIR)/esp/EFI/BOOT/BOOTX64.EFI
	cp -f /usr/share/OVMF/OVMF_VARS_4M.fd $(BUILDDIR)/vars.fd
	qemu-system-x86_64 -machine q35,accel=kvm:tcg -cpu max -m 512M -nographic \
		-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
		-drive if=pflash,format=raw,file=$(BUILDDIR)/vars.fd \
		-drive format=raw,file=fat:rw:$(BUILDDIR)/esp

clean:
	$(MAKE) -C $(R2DIR) clean
	rm -rf $(BUILDDIR)
