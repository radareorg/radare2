include ../../config.mk
# XXX
CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
LDFLAGS+=${LINK}

foo: all

ALL_TARGETS=
ALGOS=aes.mk
include $(ALGOS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d

.PHONY: all clean foo mrproper
