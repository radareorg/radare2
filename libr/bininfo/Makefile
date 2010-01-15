NAME=r_bininfo
DEPS=r_lib r_util


include ../config.mk
foo: pre libr_bininfo.${EXT_SO} plugins

CFLAGS+=-DCORELIB -Iformat
#XXX
CFLAGS+=-DLIL_ENDIAN=1
include ${STATIC_BININFO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst bininfo_,p/bininfo_,$(STATIC_OBJ)))
OBJ=bininfo.o ${STATIC_OBJS}

pre:
	if [ ! -e libr_bininfo.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
