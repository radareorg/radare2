include ../../config.mk
include ../../../mk/platform.mk

LINK+=-L../../util -lr_util
LDFLAGS+=${LINK}

nop:

foo: all

ALL_TARGETS=
CFLAGS+=-I../../include
ALGOS=aes.mk aes_cbc.mk
include $(ALGOS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
