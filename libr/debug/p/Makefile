include ../../config.mk

ifeq ($(WITHPIC),1)
CFLAGS+=-I../../include -Wall ${PIC_FLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}.. -DR2_PLUGIN_INCORE

all: ${ALL_TARGETS}

ALL_TARGETS=
DEBUGS=native.mk gdb.mk qnx.mk winkd.mk bochs.mk
include $(DEBUGS)

pre:
	@cd libgdbwrap && ${MAKE}

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

	

mrproper: clean
	-rm -f *.d */*.d
else
all clean mrproper:
endif

.PHONY: all clean mrproper sync

M=mini-rv32ima
sync:
	git clone https://github.com/cnlohr/$M
	cp -f $M/$M/$M.h $M.h
