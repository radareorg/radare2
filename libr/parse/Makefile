NAME=r_parse
DEPS=r_lib r_flags r_util r_anal

-include ../config.mk
foo: pre libr_parse.${EXT_SO} libr_parse.${EXT_AR} plugins bins

CFLAGS+=-DCORELIB
-include ${STATIC_PARSE_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst parse_,p/parse_,$(STATIC_OBJ)))
OBJ=parse.o ${STATIC_OBJS}

bins:
	cd t && ${MAKE} all

pre:
	@if [ ! -e libr_parse.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
