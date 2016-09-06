include ../config.mk
include ../../global.mk

NAME=r_bin
DEPS=r_util r_io r_socket r_magic

.PHONY: pre

pre: $(LIBSO) $(LIBAR)
	$(MAKE) -C p
	$(MAKE) -C d

CFLAGS+=-DCORELIB -Iformat -Imangling

include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/bin/p/, $(STATIC_OBJ))
OBJS=bin.o dbginfo.o bin_write.o demangle.o dwarf.o filter.o
OBJS+=mangling/cxx/cp-demangle.o ${STATIC_OBJS}
OBJS+=mangling/demangler.o
OBJS+=mangling/microsoft_demangle.o
OBJS+=mangling/objc.o mangling/cxx.o mangling/msvc.o
OBJS+=mangling/swift.o mangling/swift-sd.o
OBJS+=mangling/dlang.o
OBJS+=pdb/pdb_downloader.o pdb/omap.o pdb/stream_pe.o pdb/gdata.o
OBJS+=pdb/fpo.o pdb/dbi.o pdb/tpi.o pdb/stream_file.o pdb/pdb.o
LINK+=$(SHLR)/java/libr_java.a

include $(TOP)/libr/rules.mk
