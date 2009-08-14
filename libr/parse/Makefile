NAME=r_parse
DEPS=r_lib

foo: pre libr_parse.so plugins bins

CFLAGS+=-DCORELIB
include ../config.mk
include ${STATIC_PARSE_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst parse_,p/parse_,$(STATIC_OBJ)))
OBJ=parse.o ${STATIC_OBJS}

bins:
	cd t && ${MAKE} all

pre:
	@if [ ! -e libr_parse.so ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
