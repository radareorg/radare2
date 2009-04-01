NAME=r_bininfo
DEPS=r_lib r_util

foo: pre libr_bininfo.so plugins

CFLAGS+=-DCORELIB -Iformat
#XXX
CFLAGS+=-D__UNIX__=1 -DLIL_ENDIAN=1
include ../config-user.mk
include ${STATIC_BININFO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bininfo_,p/bininfo_,$(STATIC_OBJ)))
OBJ=bininfo.o ${STATIC_OBJS}

pre:
	if [ ! -e libr_bininfo.so ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
