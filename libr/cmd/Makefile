NAME=r_cmd
OBJS=cmd.o plugin.o macro.o
DEPS=r_util r_cons r_core r_anal

include ../config.mk

CFLAGS+=-DCORELIB

foo:
	for a in ${LIBSO} ${LIBAR} plugins ; do ${MAKE} $$a ; done

include ${STATIC_CMD_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst cmd_,p/cmd_,$(STATIC_OBJ)))
OBJS+=${STATIC_OBJS}

plugins:
	cd p && ${MAKE} all

include ../rules.mk
