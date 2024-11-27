include ../../../../../global.mk

ARCH_ARM64_COMMIT=cb7a22763c112e6ca99558edec2b6a9137234fdc
ARCH_ARMV7_COMMIT=f270a6cc99644cb8e76055b6fa632b25abd26024

EXT_AR=a

all: arch-arm64 arch-armv7
	$(MAKE) arm64dis.$(EXT_AR)
	$(MAKE) armv7dis.$(EXT_AR)

V35ARM64_HOME=$(CURDIR)

include deps.mk

CFLAGS+=$(V35ARM64_CFLAGS) -fPIC
CFLAGS+=$(V35ARMV7_CFLAGS) -fPIC
ALIBS=$(addprefix arch-arm64/disassembler/,$(V35ARM64_OBJS))
ALIBS+=$(addprefix arch-armv7/armv7_disasm/,$(V35ARMV7_OBJS))
RANLIB?=ranlib
EXT_AR?=a

clean:
	rm -rf arch-armv7 armv7dis.$(EXT_AR)

mrproper: clean
	rm -rf arch-arm64

.PHONY: all clean

$(ALIBS): arch-arm64 arch-armv7

## ARM64
arch-arm64:
	git clone -q https://github.com/radareorg/vector35-arch-arm64 arch-arm64
	cd arch-arm64 && git checkout -q radare2-2024 > /dev/null && git reset --hard $(ARCH_ARM64_COMMIT)

$(V35ARM64_HOME)/arm64dis.a arm64dis.a: $(ALIBS)
	rm -f arm64dis.$(EXT_AR)
	$(AR) q arm64dis.$(EXT_AR) $(ALIBS)
	$(RANLIB) arm64dis.$(EXT_AR)

## ARMV7
arch-armv7:
	git clone -q https://github.com/radareorg/vector35-arch-armv7 arch-armv7
	cd arch-armv7 && git checkout -q radare2 > /dev/null && git reset --hard $(ARCH_ARMV7_COMMIT)

$(V35ARMV7_HOME)/armv7dis.a armv7dis.a: $(ALIBS)
	rm -f armv7dis.$(EXT_AR)
	$(AR) q armv7dis.$(EXT_AR) $(ALIBS)
	$(RANLIB) armv7dis.$(EXT_AR)
