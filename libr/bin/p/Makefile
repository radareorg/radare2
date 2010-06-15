include ../../config.mk

#include ../../../config-user.mk
CFLAGS=-I../../include -I../format/ -Wall -fPIC
CFLAGS+=${LDFLAGS_LIB}
#CFLAGS=$CCLIB_SHARED
CFLAGS+=-L../../util -lr_util

foo: all

ALL_TARGETS=
FORMATS=elf.mk elf64.mk pe.mk pe64.mk mach0.mk mach064.mk java.mk dummy.mk
include $(FORMATS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../format/*/*.d

.PHONY: all clean foo mrproper
