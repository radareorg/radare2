include ../../config.mk

CFLAGS=-I../../include -I../arch -I../../asm/arch -Wall -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
CFLAGS+=-L../../util -lr_util

foo: all

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=dummy.mk x86.mk x86_bea.mk ppc.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

.PHONY: all clean foo
