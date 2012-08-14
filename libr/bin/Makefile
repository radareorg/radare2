include ../../global.mk

NAME=r_bin
DEPS=r_lib r_util

foo:
	for a in pre libr_bin.${EXT_SO} libr_bin.${EXT_AR} plugins ; do ${MAKE} $$a ; done

CFLAGS+=-DCORELIB -Iformat -Imangling

include $(TOP)/libr/config.mk
include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/bin/p/, $(STATIC_OBJ))
OBJ=bin.o bin_meta.o bin_write.o demangle.o dwarf.o ${STATIC_OBJS}
OBJ+=mangling/cxx/cp-demangle.o

pre:
	@if [ ! -e libr_bin.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi
	${MAKE} ${LIBSO}

plugins:
	cd p && ${MAKE} all

include $(TOP)/libr/rules.mk
