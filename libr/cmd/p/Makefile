include ../../config.mk

CFLAGS=-I../../include -Wall -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
# XXX
CFLAGS+=-DLIL_ENDIAN=1
#CFLAGS+=-L../../util -lr_util

foo: all

ALL_TARGETS=
PLUGS=dummy.mk
include $(PLUGS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
