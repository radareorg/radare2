include ../../config.mk

CFLAGS=-I../../include -I../arch -Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
CFLAGS+=-L../../util -lr_util
LDFLAGS+=${LINK}

foo: all

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=dummy.mk x86.mk x86_x86im.mk ppc.mk arm.mk
include $(ARCHS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean foo mrproper
