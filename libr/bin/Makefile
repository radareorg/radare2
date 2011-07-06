NAME=r_bin
DEPS=r_lib r_util

include ../config.mk

foo: pre libr_bin.${EXT_SO} libr_bin.${EXT_AR} plugins

# XXX
CFLAGS+=-DCORELIB -Iformat -Imangling

include ../config.mk
include ${STATIC_BIN_PLUGINS}
include ${STATIC_BIN_XTR_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bin_,p/bin_,$(STATIC_OBJ)))
OBJ=bin.o bin_meta.o bin_write.o demangle.o ${STATIC_OBJS}
OBJ+=mangling/cxx/cp-demangle.o

pre:
	@if [ ! -e libr_bin.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
