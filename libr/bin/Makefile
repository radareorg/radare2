include ../config.mk
include ../../global.mk

include ../db/build.mk
LDFLAGS+=${DL_LIBS}

NAME=r_bin
DEPS=r_lib r_util

.PHONY: pre

pre: $(LIBSO) $(LIBAR)
	@cd p && ${MAKE}
	#@${MAKE} -C p all

CFLAGS+=-DCORELIB -Iformat -Imangling

include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/bin/p/, $(STATIC_OBJ))
OBJS=bin.o bin_meta.o bin_write.o demangle.o dwarf.o
OBJS+=mangling/cxx/cp-demangle.o ${STATIC_OBJS}
OBJS+=mangling/objc.o mangling/cxx.o

include $(TOP)/libr/rules.mk
