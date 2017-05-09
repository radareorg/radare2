include ../../config.mk
include ../../../mk/platform.mk

CFLAGS+=-I$(LTOP)/include -I$(LTOP)/bin/format/ -Wall $(PIC_CFLAGS)
ifeq ($(CC),cccl)
LDFLAGS+=-L$(LTOP)/util -llibr_util
LDFLAGS+=-L$(LTOP)/bin -llibr_bin
LDFLAGS+=-L$(LTOP)/io -llibr_io
else
LDFLAGS+=-L$(LTOP)/util -lr_util
LDFLAGS+=-L$(LTOP)/bin -lr_bin
LDFLAGS+=-L$(LTOP)/io -lr_io
endif
SHLR=$(LTOP)/../shlr

foo: all

ALL_TARGETS=
FORMATS=any.mk elf.mk elf64.mk pe.mk pe64.mk te.mk mach0.mk
FORMATS+=bios.mk mach064.mk fatmach0.mk dyldcache.mk java.mk
FORMATS+=dex.mk fs.mk ningb.mk coff.mk ningba.mk xbe.mk zimg.mk
FORMATS+=omf.mk cgc.mk dol.mk nes.mk mbn.mk psxexe.mk spc700.mk
FORMATS+=vsf.mk nin3ds.mk xtr_dyldcache.mk bflt.mk wasm.mk sfc.mk
include $(FORMATS)

all: ${ALL_TARGETS}
	@true

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d $(TOP)/libr/bin/format/*/*.d

.PHONY: all clean foo mrproper
