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

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
FORMATS=any.mk elf.mk elf64.mk pe.mk pe64.mk te.mk mach0.mk
FORMATS+=bios.mk mach064.mk dyldcache.mk xnu_kernelcache.mk java.mk
FORMATS+=dex.mk fs.mk ningb.mk coff.mk ningba.mk xbe.mk zimg.mk
FORMATS+=omf.mk cgc.mk dol.mk nes.mk mbn.mk psxexe.mk
FORMATS+=vsf.mk nin3ds.mk bflt.mk wasm.mk sfc.mk
FORMATS+=mdmp.mk z64.mk qnx.mk prg.mk dmp64.mk

FORMATS+=xtr_dyldcache.mk
FORMATS+=xtr_fatmach0.mk
FORMATS+=xtr_sep64.mk

include $(FORMATS)

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d $(TOP)/libr/bin/format/*/*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
