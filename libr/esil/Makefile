include ../config.mk

NAME=r_esil
R2DEPS+=r_util r_reg r_io

CFLAGS+=-DR2_PLUGIN_INCORE
CFLAGS:=-I.. -I$(LTOP)/asm/esil/include -DR2_PLUGIN_INCORE -Iesil -I$(TOP)/shlr $(CFLAGS)

.PHONY: pre
pre: libr_esil.$(EXT_SO) libr_esil.$(EXT_AR)
	$(MAKE) -C p

include $(STATIC_ESIL_PLUGINS)
STATIC_OBJS=$(subst ..,p/..,$(subst esil_,p/esil_,$(STATIC_OBJ)))
OBJS=esil.o esil_plugin.o esil_handler.o esil_stats.o esil_trace.o
OBJS+=${STATIC_OBJS}

include ../rules.mk
