CFLAGS=-I../../include -I../format/ -Wall -fPIC -shared -Wl,-R..
# XXX
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__ -g -DR_DEBUG=0

foo: all

ALL_TARGETS=
FORMATS=elf.mk elf64.mk pe.mk java.mk
include $(FORMATS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

.PHONY: all clean foo
