include ../config.mk
include ../../global.mk

NAME=r_bin
DEPS=r_util r_db r_io r_magic

.PHONY: pre

pre: $(LIBSO) $(LIBAR)
	$(MAKE) -C p
	$(MAKE) -C d

CFLAGS+=-DCORELIB -Iformat -Imangling

include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/bin/p/, $(STATIC_OBJ))
OBJS=bin.o dbginfo.o bin_write.o demangle.o dwarf.o
OBJS+=mangling/cxx/cp-demangle.o ${STATIC_OBJS}
OBJS+=mangling/objc.o mangling/cxx.o
OBJS+=pdb/pdb_downloader.o pdb/omap.o pdb/pe.o pdb/gdata.o pdb/fpo.o pdb/dbi.o pdb/tpi.o pdb/stream_file.o pdb/pdb.o
LINK+=$(SHLR)/java/libr_java.a

include $(TOP)/libr/rules.mk
