include ../config.mk

NAME=r_lang
OBJS=lang.o
R2DEPS=r_util r_cons
CFLAGS+=-DR2_PLUGIN_INCORE

ifeq ($(USE_SYSMUJS),1)
CFLAGS+=-DUSE_SYSMUJS=1
CFLAGS+=$(MUJS_CFLAGS)
LDFLAGS+=$(MUJS_LDFLAGS)
endif

include ../rules.mk
