NAME=r_bp

foo: pre libr_bp.so plugins

CFLAGS+=-DCORELIB
include ../config.mk
include ${STATIC_BP_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bp_,p/bp_,$(STATIC_OBJ)))
OBJ=bp.o io.o handle.o traptrace.o ${STATIC_OBJS}

pre:
	if [ ! -e libr_bp.so ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
