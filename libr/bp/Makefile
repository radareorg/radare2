include ../config.mk

NAME=r_bp
DEPS+=r_util

CFLAGS+=-DCORELIB

.PHONY: pre
pre: libr_bp.${EXT_SO} libr_bp.${EXT_AR}
	${MAKE} -C p

include ${STATIC_BP_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bp_,p/bp_,$(STATIC_OBJ)))
OBJS=bp.o watch.o io.o plugin.o traptrace.o ${STATIC_OBJS}

include ../rules.mk
