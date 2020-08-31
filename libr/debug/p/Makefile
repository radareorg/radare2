include ../../config.mk

ifeq ($(WITHPIC),1)
CFLAGS+=-I../../include -Wall ${PIC_FLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DR2_PLUGIN_INCORE

all: ${ALL_TARGETS}

ALL_TARGETS=
DEBUGS=native.mk gdb.mk qnx.mk windbg.mk bochs.mk
include $(DEBUGS)

pre:
	@cd libgdbwrap && ${MAKE}

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d */*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
