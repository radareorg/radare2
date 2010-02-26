NAME=r_cmd
OBJ=cmd.o handle.o
DEPS=r_util

include ../config.mk

CFLAGS+=-DCORELIB

foo: ${LIBSO} ${LIBAR} plugins

include ${STATIC_CMD_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst cmd_,p/cmd_,$(STATIC_OBJ)))
OBJ+=${STATIC_OBJS}

plugins:
	cd p && ${MAKE} all

include ../rules.mk
