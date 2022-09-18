include ../config.mk

NAME=r_arch
R2DEPS+=r_util

CFLAGS+=-DR2_PLUGIN_INCORE

.PHONY: pre
pre: libr_arch.$(EXT_SO) libr_arch.$(EXT_AR)
	$(MAKE) -C p

include $(STATIC_ARCH_PLUGINS)
STATIC_OBJS=$(subst ..,p/..,$(subst arch_,p/arch_,$(STATIC_OBJ)))
OBJS=arch.o api.o decoder.o ${STATIC_OBJS}

include ../rules.mk
