include ../../../../../global.mk

EXT_AR=a

all: v35arm64.$(EXT_AR) v35armv7.$(EXT_AR)

include deps.mk

CFLAGS+=$(V35ARM64_CFLAGS) -fPIC
CFLAGS+=$(V35ARMV7_CFLAGS) -fPIC
# V35OBJS=$(addprefix $(SPRJ)/v35arm64/disassembler/,$(V35ARM64_OBJS))
V35OBJS=$(addprefix $(SPRJ)/binaryninja/arch/arm64/disassembler/,$(V35ARM64_OBJS))
# V35OBJS+=$(addprefix $(SPRJ)/v35armv7/armv7_disasm/,$(V35ARMV7_OBJS))
V35OBJS+=$(addprefix $(SPRJ)/binaryninja/arch/armv7/arm7_disasm/,$(V35ARMV7_OBJS))
RANLIB?=ranlib
EXT_AR?=a

clean:
	rm -f v35arm64.$(EXT_AR) v35armv7.$(EXT_AR)

mrproper: clean
	rm -rf arch-arm64

.PHONY: all clean

$(V35OBJS): arch-arm64 arch-armv7

## ARM64
arch-arm64: $(SPRJ)/binaryninja/arch/v35arm64
arch-armv7: $(SPRJ)/binaryninja/arch/v35armv7

$(SPRJ)/binaryninja/arch/v35armv7 $(SPRJ)/binaryninja/arch/v35arm64:
	$(MAKE) -C $(SPRJ)

v35arm64.a: $(V35OBJS)
	rm -f v35arm64.$(EXT_AR)
	$(AR) q v35arm64.$(EXT_AR) $(V35OBJS)
	$(RANLIB) v35arm64.$(EXT_AR)

v35armv7.a: $(V35OBJS)
	rm -f v35armv7.$(EXT_AR)
	$(AR) q v35armv7.$(EXT_AR) $(V35OBJS)
	$(RANLIB) v35armv7.$(EXT_AR)
