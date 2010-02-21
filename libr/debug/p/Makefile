include ../../config.mk

CFLAGS=-I../../include -Wall -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DCORELIB

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

.PHONY: all clean
