include ../../global.mk

NAME=r_bin
DEPS=r_lib r_util

foo:
	for a in $(LIBSO) ${LIBAR} plugins ; do ${MAKE} $$a ; done

CFLAGS+=-DCORELIB -Iformat -Imangling

include $(TOP)/libr/config.mk
include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/bin/p/, $(STATIC_OBJ))
OBJ=bin.o bin_meta.o bin_write.o demangle.o dwarf.o ${STATIC_OBJS}
OBJ+=mangling/cxx/cp-demangle.o

plugins:
	cd p && ${MAKE} all

include $(TOP)/libr/rules.mk
