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
FORMATS=null.mk elf.mk elf64.mk pe.mk pe64.mk te.mk mach0.mk
FORMATS+=bios.mk ftab.mk gns1.mk mach064.mk dyldcache.mk xnu_kernelcache.mk java.mk
FORMATS+=dex.mk fs.mk ningb.mk coff.mk xcoff64.mk ningba.mk xbe.mk zimg.mk
FORMATS+=omf.mk cgc.mk dol.mk rel.mk nes.mk mbn.mk psxexe.mk
FORMATS+=vsf.mk nin3ds.mk bflt.mk wasm.mk sfc.mk uf2.mk
FORMATS+=mdmp.mk z64.mk qnx.mk prg.mk dmp64.mk xtac.mk pef.mk mdt.mk som.mk

FORMATS+=xtr_dyldcache.mk xtr_ftab.mk

DEMANGLERS=cxx_demangle.mk dlang_demangle.mk ibmxl_demangle.mk
DEMANGLERS+=java_demangle.mk msvc_demangle.mk objc_demangle.mk
DEMANGLERS+=pascal_demangle.mk rust_demangle.mk swift_demangle.mk

include $(FORMATS) $(DEMANGLERS)

clean:
	-rm -f *.so *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d $(TOP)/libr/bin/format/*/*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
