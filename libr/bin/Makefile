NAME=r_bin
DEPS=r_lib r_util

foo: pre libr_bin.so plugins

CFLAGS+=-DCORELIB -Iformat
#XXX
CFLAGS+=-D__UNIX__=1 -DLIL_ENDIAN=1
include ../config.mk
include ${STATIC_BIN_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bin_,p/bin_,$(STATIC_OBJ)))
OBJ=bin.o ${STATIC_OBJS}

pre:
	if [ ! -e libr_bin.so ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
