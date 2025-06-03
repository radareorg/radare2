include ../config.mk
include ../../global.mk

NAME=r_bin
R2DEPS=r_util r_io r_socket r_magic r_syscall r_cons r_muta r_fs

.PHONY: pre

pre: $(LIBSO) $(LIBAR)
	$(MAKE) -C p
	$(MAKE) -C d || true

CFLAGS+=-DR2_PLUGIN_INCORE -Iformat -Imangling

include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}
include ${STATIC_BIN_LDR_PLUGINS}
include $(SHLR)/java/deps.mk
include $(SHLR)/ar/deps.mk
include $(LIBR)/magic/deps.mk

STATIC_OBJS=$(addprefix $(LTOP)/bin/p/, $(STATIC_OBJ))
OBJS=bin.o addrline.o bin_ldr.o bin_write.o demangle.o
OBJS+=dwarf.o bfilter.o bfile.o bobj.o blang.o
OBJS+=mangling/cxx/cp-demangle.o ${STATIC_OBJS}
OBJS+=mangling/demangler.o
OBJS+=mangling/microsoft.o
OBJS+=mangling/objc.o mangling/cxx.o mangling/msvc.o
OBJS+=mangling/swift.o mangling/swift-sd.o
OBJS+=mangling/java.o
OBJS+=mangling/pascal.o
OBJS+=mangling/rust.o

include $(TOP)/libr/bin/format/pdb/deps.mk
include $(TOP)/libr/rules.mk
