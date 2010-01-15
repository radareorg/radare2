include ../../config.mk
# XXX
CFLAGS=-I../../include -I../arch/ -I../arch/include -Wall -fPIC -shared -Wl,-R..

foo: all

ALL_TARGETS=
ALGOS=aes.mk
include $(ALGOS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

.PHONY: all clean foo
