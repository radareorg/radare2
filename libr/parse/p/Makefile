include ../../config.mk
include ../../../mk/platform.mk
include ../../../shlr/zip/deps.mk

CFLAGS+=-I../../include -Wall ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# -D__UNIX__
CFLAGS+=-DCORELIB
LDFLAGS+=${LINK}

foo: all

ALL_TARGETS=
ARCHS=att2intel.mk x86_pseudo.mk mreplace.mk
ARCHS+=arm_pseudo.mk z80_pseudo.mk ppc_pseudo.mk 6502_pseudo.mk
ARCHS+=m68k_pseudo.mk

include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d */*.d

.PHONY: all clean foo mrproper
