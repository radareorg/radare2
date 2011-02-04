include ../../config.mk

CFLAGS=-I../../include -Wall -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
# -D__UNIX__
CFLAGS+=-DCORELIB

foo: all

ALL_TARGETS=
ARCHS=x86_pseudo.mk mreplace.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d */*.d

.PHONY: all clean foo mrproper
