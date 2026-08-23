# builds radare2 as an EFI application (BOOTX64.EFI) using clang + lld

.PHONY: all configure build link clean run

R2DIR=../..
BUILDDIR=$(R2DIR)/build-uefi
LDS?=/usr/lib/elf_x86_64_efi.lds
CRT0?=/usr/lib/crt0-efi-x86_64.o
CC=clang
LLD?=ld.lld
OBJCOPY?=objcopy

MESON_FLAGS=-Duse_zip=false -Dstatic_runtime=true -Duse_sys_zlib=false \
	-Duse_sys_magic=false -Duse_sys_openssl=false -Denable_tests=false \
	-Dplugins= -Duse_fork=false -Duse_dylink=false -Ddebugger=false \
	-Dcli=disabled -Dwant_qjs=false -Dwant_zydis=false -Dwant_threads=false

UEFI_CFLAGS=-DR2_UEFI=1 -D__thread= -D_GNU_SOURCE -ffreestanding -fno-stack-protector \
	-mno-red-zone -fPIC -nostdlibinc -isystem /usr/include/x86_64-linux-musl \
	-I/usr/include/efi -I/usr/include/efi/x86_64 \
	-I$(R2DIR)/libr/include -I$(BUILDDIR) -I$(R2DIR)/subprojects/sdb/include

R2LIBS=$(wildcard $(BUILDDIR)/libr/*/libr_*.a) \
	$(BUILDDIR)/subprojects/capstone-v5/libcapstone.a \
	$(BUILDDIR)/subprojects/qjs/libqjs.a \
	$(BUILDDIR)/subprojects/sdb/liblibsdb_static.a \
	$(wildcard $(BUILDDIR)/shlr/*.a)

all: build link

configure:
	cd $(R2DIR) && meson setup build-uefi --cross-file dist/uefi/cross-uefi.ini $(MESON_FLAGS)

$(BUILDDIR)/build.ninja:
	$(MAKE) configure

build: $(BUILDDIR)/build.ninja
	cd $(R2DIR) && meson compile -C build-uefi

link: $(BUILDDIR)/BOOTX64.EFI

$(BUILDDIR)/main.o: main.c
	$(CC) -c -o $@ $< $(UEFI_CFLAGS)

$(BUILDDIR)/relocate.o: relocate.c
	$(CC) -c -o $@ $< $(UEFI_CFLAGS)

# lld does not write the implicit addends that the gnu-efi _relocate expects,
# so relocate.o provides a rela-aware replacement for it
$(BUILDDIR)/r2efi.so: $(BUILDDIR)/main.o $(BUILDDIR)/relocate.o
	$(LLD) -nostdlib -shared -Bsymbolic --no-undefined -znocombreloc \
		-T $(LDS) $(CRT0) $(BUILDDIR)/relocate.o $(BUILDDIR)/main.o \
		--start-group $(R2LIBS) --end-group -o $@

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
	rm -rf $(BUILDDIR)
