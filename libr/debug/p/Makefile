CFLAGS=-I../../include -Wall -fPIC -shared -Wl,-R.. -DCORELIB

foo: all

ALL_TARGETS=
DEBUGS=ptrace.mk gdb.mk
include $(DEBUGS)

all: pre ${ALL_TARGETS}
	@true

pre:
	cd dbg_libgdbwrap && ${MAKE}

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

.PHONY: all clean
