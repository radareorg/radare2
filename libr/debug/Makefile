include ../config.mk

NAME=r_debug
DEPS=r_reg r_anal r_bp r_util r_io r_parse r_cons r_db r_syscall
CFLAGS+=-DCORELIB

foo:
	@${MAKE} libs
	@${MAKE} plugins

include ../config.mk
include ${STATIC_DEBUG_PLUGINS}

STATIC_OBJS=$(subst ..,p/..,$(subst debug_,p/debug_,$(STATIC_OBJ)))

OBJS=signal.o map.o trace.o arg.o debug.o plugin.o
OBJS+=pid.o reg.o desc.o ${STATIC_OBJS}

plugins:
	cd p && ${MAKE} all

include ../rules.mk

libs: ${LIBSO} ${LIBAR}
.PHONY: foo plugins tests libs
