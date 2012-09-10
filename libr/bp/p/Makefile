include ../../config.mk
ifeq ($(WITHPIC),1)

CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC ${LDFLAGS_LIB}
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__

foo: all

ALL_TARGETS=
ARCHS=x86.mk arm.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
else
all:
endif
