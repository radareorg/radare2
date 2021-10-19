
all: arch-arm64
	$(MAKE) arm64dis.$(EXT_AR)

include deps.mk

CFLAGS+=$(V35ARM64_CFLAGS) -fPIC
ALIBS=$(addprefix arch-arm64/disassembler/,$(V35ARM64_OBJS))
RANLIB?=ranlib
EXT_AR?=a

clean:
	rm -rf arch-arm64 arm64dis.$(EXT_AR)

mrproper: clean
	rm -rf arch-arm64

.PHONY: all clean

ARCH_ARM64_COMMIT=91ff0d24ab189263eed241bc551484a2d0af69ec

$(ALIBS): arch-arm64

arch-arm64:
	git clone -q https://github.com/radareorg/vector35-arch-arm64 arch-arm64
	cd arch-arm64 && git checkout -q radare2 > /dev/null && git reset --hard $(ARCH_ARM64_COMMIT)

$(V35ARM64_HOME)/arm64dis.a arm64dis.a: $(ALIBS)
	rm -f arm64dis.$(EXT_AR)
	$(AR) q arm64dis.$(EXT_AR) $(ALIBS)
	$(RANLIB) arm64dis.$(EXT_AR)
