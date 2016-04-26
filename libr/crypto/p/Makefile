include ../../config.mk
include ../../../mk/platform.mk

LDFLAGS+=${LINK}

caca:

foo: all

ALL_TARGETS=
ALGOS=aes.mk aes_cbc.mk
include $(ALGOS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
