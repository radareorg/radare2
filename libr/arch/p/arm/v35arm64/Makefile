EXT_AR?=a

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
	rm -rf arch-arm64 arm64dis.$(EXT_AR)
	rm -rf arch-armv7 armv7dis.$(EXT_AR)

mrproper: clean
	rm -rf arch-arm64

.PHONY: all clean

ARCH_ARM64_COMMIT=194c539228d0a1ba292bfeef3f4f53da9a8db7bd
ARCH_ARMV7_COMMIT=83cf0f2918d98d7cb7b85493619c7a96406e415d

$(ALIBS): arch-arm64 arch-armv7

## ARM64
arch-arm64:
	git clone -q https://github.com/radareorg/vector35-arch-arm64 arch-arm64
	cd arch-arm64 && git checkout -q radare2-wip > /dev/null && git reset --hard $(ARCH_ARM64_COMMIT)

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
