include ../../config.mk
include ../../../mk/platform.mk
include ../../../shlr/zip/deps.mk

CFLAGS+=-I../../include -Wall ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# -D__UNIX__
CFLAGS+=-DR2_PLUGIN_INCORE
LDFLAGS+=${LINK}

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
ARCHS=att2intel.mk x86_pseudo.mk chip8_pseudo.mk
ARCHS+=arm_pseudo.mk z80_pseudo.mk ppc_pseudo.mk 6502_pseudo.mk
ARCHS+=m68k_pseudo.mk sh_pseudo.mk avr_pseudo.mk wasm_pseudo.mk
include $(ARCHS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d */*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
