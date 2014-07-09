include ../config.mk

NAME=r_parse
DEPS=r_flags r_util r_anal

LINK+=$(STOP)/tcc/libr_tcc.a
CFLAGS+=-I$(STOP)/tcc/

foo:
	@for a in pre libr_parse.${EXT_SO} \
	libr_parse.${EXT_AR} plugins bins \
	; do ${MAKE} $$a ; done

CFLAGS+=-DCORELIB
-include ${STATIC_PARSE_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst parse_,p/parse_,$(STATIC_OBJ)))
OBJS=parse.o code.o ${STATIC_OBJS}

bins:
#	@cd t && ${MAKE} all

pre:
ifeq ($(WITHNONPIC),1)
	@if [ ! -e libr_parse.${EXT_AR} ]; then rm -f ${STATIC_OBJS} ; fi
endif
ifeq ($(WITHPIC),1)
	@if [ ! -e libr_parse.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi
endif

plugins:
	@cd p && ${MAKE} all

include ../rules.mk
