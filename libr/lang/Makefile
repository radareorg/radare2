include ../config.mk

NAME=r_lang
OBJS=lang.o
R2DEPS+=r_util
R2DEPS+=r_io
R2DEPS+=r_socket
R2DEPS+=r_cons
R2DEPS+=r_reg
R2DEPS+=r_asm
R2DEPS+=r_muta
R2DEPS+=r_arch
R2DEPS+=r_esil
R2DEPS+=r_search
R2DEPS+=r_syscall
R2DEPS+=r_flag
CFLAGS+=-DR2_PLUGIN_INCORE
CFLAGS+=-DCONFIG_VERSION=\"0.0.0\"
LDFLAGS+=$(LIBATOMIC)
LDFLAGS+=-lm

ifeq ($(WANT_QJS),1)
OBJS+=$(QJS_OBJS)
include ../../shlr/qjs/deps.mk
endif
include ../rules.mk
