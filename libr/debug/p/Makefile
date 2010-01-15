include ../../config.mk

CFLAGS=-I../../include -Wall -fPIC -shared -Wl,-R.. -DCORELIB

foo: all

ALL_TARGETS=
DEBUGS=ptrace.mk gdb.mk
include $(DEBUGS)

#all: pre ${ALL_TARGETS}
all: ${ALL_TARGETS}
	@true

pre:
	@cd libgdbwrap && ${MAKE}

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

.PHONY: all clean
