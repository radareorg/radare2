NAME=r_debug
DEPS=r_reg r_anal r_bp r_util r_io r_parse r_cons
CFLAGS+=-DCORELIB

foo:
	@${MAKE} pre
	@${MAKE} libs
	@${MAKE} tests
	@${MAKE} plugins

include ../config.mk
include ${STATIC_DEBUG_PLUGINS}

STATIC_OBJS=$(subst ..,p/..,$(subst debug_,p/debug_,$(STATIC_OBJ)))

OBJ=map.o trace.o arg.o debug.o plugin.o pid.o reg.o desc.o ${STATIC_OBJS}

pre:
	@if [ ! -e libr_debug.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

tests:
	cd t && ${MAKE} all

plugins:
	cd p && ${MAKE} all

include ../rules.mk

libs: ${LIBSO} ${LIBAR}
