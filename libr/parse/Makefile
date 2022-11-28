include ../config.mk

NAME=r_parse
R2DEPS=r_flag r_util r_syscall r_reg
# indirect dependencies
R2DEPS+=r_cons

CFLAGS+=-Ic

# LINK+=$(STOP)/mpc/libmpc.a
# CFLAGS+=-I$(STOP)/mpc/

include $(SHLR)/zip/deps.mk

foo:
	@for TARGET in pre libr_parse.${EXT_SO} \
	libr_parse.${EXT_AR} plugins bins ; do \
	    ${MAKE} $$TARGET ; done

CFLAGS+=-DR2_PLUGIN_INCORE
-include ${STATIC_PARSE_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst parse_,p/parse_,$(STATIC_OBJ)))
OBJS=parse.o filter.o ${STATIC_OBJS}
# OBJS+=c/tccgen.o c/tccpp.o c/libtcc.o

pre:

bins:
#	@cd t && ${MAKE} all

plugins:
	@cd p && ${MAKE} all

.PHONY: sdb-sync sync-sdb sdbclean

include ../rules.mk
