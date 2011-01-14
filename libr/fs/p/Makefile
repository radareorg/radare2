include ../../config.mk

CFLAGS+=-I../../include -Wall -shared -fPIC ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
#CFLAGS+=-I../../include
LDFLAGS+=${LINK}

foo: all

ALL_TARGETS=
# TODO: rename to enabled plugins
FSS=ext2.mk
include $(FSS)

all: grublib ${ALL_TARGETS}
	@true

grublib:
	cd grub && ${MAKE} lib

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}
	cd grub && ${MAKE} clean

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean foo mrproper
