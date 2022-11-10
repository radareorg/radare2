include ../config.mk

NAME=r_arch
R2DEPS+=r_util r_reg

CFLAGS+=-DR2_PLUGIN_INCORE
CFLAGS:=-I.. -I$(LTOP)/asm/arch/include -DR2_PLUGIN_INCORE -Iarch -I$(TOP)/shlr $(CFLAGS)

.PHONY: pre
pre: libr_arch.$(EXT_SO) libr_arch.$(EXT_AR)
	$(MAKE) -C p

include $(STATIC_ARCH_PLUGINS)
STATIC_OBJS=$(subst ..,p/..,$(subst arch_,p/arch_,$(STATIC_OBJ)))
OBJS=arch.o aconfig.o switchop.o archop.o archvalue.o archcond.o session.o
OBJS+=${STATIC_OBJS}

include ../rules.mk
