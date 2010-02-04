NAME=r_debug
DEPS=r_reg r_bp r_util
CFLAGS+=-DCORELIB

foo: pre libs tests plugins

include ../config.mk
include ${STATIC_DEBUG_PLUGINS}

STATIC_OBJS=$(subst ..,p/..,$(subst debug_,p/debug_,$(STATIC_OBJ)))

OBJ=map.o debug.o handle.o pid.o reg.o ${STATIC_OBJS}

pre:
	@if [ ! -e libr_debug.so ]; then rm -f ${STATIC_OBJS} ; fi

tests:
	cd t && ${MAKE} all

plugins:
	cd p && ${MAKE} all

include ../rules.mk

libs: ${LIBSO} ${LIBAR}
