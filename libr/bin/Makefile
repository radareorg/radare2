include ../config.mk
include ../../global.mk

include ../db/build.mk
LDFLAGS+=${DL_LIBS}

NAME=r_bin
DEPS=r_util r_db

.PHONY: pre

pre: $(LIBSO) $(LIBAR)
	$(MAKE) -C p

CFLAGS+=-DCORELIB -Iformat -Imangling

include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/bin/p/, $(STATIC_OBJ))
OBJS=bin.o bin_meta.o bin_write.o demangle.o dwarf.o
OBJS+=mangling/cxx/cp-demangle.o ${STATIC_OBJS}
OBJS+=mangling/objc.o mangling/cxx.o

include $(TOP)/libr/rules.mk
