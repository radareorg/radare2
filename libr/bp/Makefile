NAME=r_bp

CFLAGS+=-DCORELIB
include ../config.mk

foo: libr_bp.${EXT_SO} libr_bp.${EXT_AR} plugins

include ${STATIC_BP_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bp_,p/bp_,$(STATIC_OBJ)))
OBJ=bp.o watch.o io.o handle.o traptrace.o ${STATIC_OBJS}

#pre:
#	if [ ! -e libr_bp.so ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
