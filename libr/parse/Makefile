include ../config.mk

NAME=r_parse
DEPS=r_flag r_util r_syscall r_reg
# indirect dependencies
DEPS+=r_cons

LINK+=$(STOP)/tcc/libr_tcc.a
CFLAGS+=-I$(STOP)/tcc/

include $(SHLR)/zip/deps.mk

foo:
	@for TARGET in pre libr_parse.${EXT_SO} \
	libr_parse.${EXT_AR} plugins bins ; do \
	    ${MAKE} $$TARGET ; done

CFLAGS+=-DCORELIB
-include ${STATIC_PARSE_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst parse_,p/parse_,$(STATIC_OBJ)))
OBJS=parse.o code.o ${STATIC_OBJS}

pre:

bins:
#	@cd t && ${MAKE} all

plugins:
	@cd p && ${MAKE} all

include ../rules.mk
