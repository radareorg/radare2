include ../../config.mk

CFLAGS=-I$(LTOP)/include -I$(LTOP)/bin/format/ -Wall -fPIC
LDFLAGS+=-L$(LTOP)/util -lr_util

foo: all

ALL_TARGETS=
FORMATS=any.mk elf.mk elf64.mk pe.mk pe64.mk te.mk mach0.mk mach064.mk fatmach0.mk dyldcache.mk java.mk dex.mk fs.mk
include $(FORMATS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d $(TOP)/libr/bin/format/*/*.d

.PHONY: all clean foo mrproper
