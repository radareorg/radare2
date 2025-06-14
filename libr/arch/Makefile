include ../config.mk
include p/capstone.mk

NAME=r_arch
R2DEPS+=r_util r_reg r_esil r_muta

CFLAGS+=-DR2_PLUGIN_INCORE
CFLAGS:=-I.. -I$(LTOP)/arch/include -DR2_PLUGIN_INCORE -Iarch -I$(TOP)/shlr $(CFLAGS)
LDFLAGS+=$(CS_LDFLAGS)

.PHONY: pre
pre: p
	$(MAKE) libr_arch.$(EXT_SO)
	$(MAKE) libr_arch.$(EXT_AR)

include $(STATIC_ARCH_PLUGINS)
include $(STOP)/java/deps.mk

STATIC_OBJS=$(subst ..,p/..,$(subst arch_,p/arch_,$(STATIC_OBJ)))
OBJS=arch.o arch_config.o arch_switch.o arch_op.o
OBJS+=arch_value.o arch_cond.o arch_session.o arch_platform.o
OBJS+=${STATIC_OBJS}

include ../rules.mk
