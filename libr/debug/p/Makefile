include ../../config.mk

CFLAGS+=-I../../include -Wall ${PIC_FLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DCORELIB

foo: all

ALL_TARGETS=
DEBUGS=native.mk gdb.mk
include $(DEBUGS)

#all: pre ${ALL_TARGETS}
all: ${ALL_TARGETS}
	@true

pre:
	@cd libgdbwrap && ${MAKE}

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d */*.d

.PHONY: all clean foo mrproper
