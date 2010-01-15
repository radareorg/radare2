include ../../config.mk

CFLAGS=-I../../include -Wall -fPIC -shared -Wl,-R..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
# -D__UNIX__
CFLAGS+=-DCORELIB

foo: all

ALL_TARGETS=
ARCHS=dummy.mk x86_pseudo.mk mreplace.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

.PHONY: all clean foo
