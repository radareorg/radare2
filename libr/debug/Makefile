NAME=r_debug
DEPS=
CFLAGS+=-DCORELIB

foo: pre libr_debug.so tests plugins

include ../config.mk
include ${STATIC_DEBUG_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst dbg_,p/dbg_,$(STATIC_OBJ)))
OBJ=debug.o handle.o pid.o reg.o ${STATIC_OBJS}

pre:
	@if [ ! -e libr_debug.so ]; then rm -f ${STATIC_OBJS} ; fi

tests:
	cd t && ${MAKE} all

plugins:
	cd p && ${MAKE} all

include ../rules.mk
