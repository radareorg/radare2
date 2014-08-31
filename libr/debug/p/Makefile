include ../../config.mk

ifeq ($(WITHPIC),1)
CFLAGS+=-I../../include -Wall ${PIC_FLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DCORELIB

foo: all

ALL_TARGETS=
DEBUGS=native.mk gdb.mk wind.mk
include $(DEBUGS)

all: ${ALL_TARGETS}
	@true

pre:
	@cd libgdbwrap && ${MAKE}

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d */*.d

.PHONY: all clean foo mrproper
else
all:
endif
