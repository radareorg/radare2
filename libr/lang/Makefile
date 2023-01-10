include ../config.mk

NAME=r_lang
OBJS=lang.o
R2DEPS=r_util r_cons r_asm
CFLAGS+=-DR2_PLUGIN_INCORE
CFLAGS+=-DCONFIG_VERSION=\"0.0.0\"
OBJS+=$(QJS_OBJS)
# LINK+=$(QJS_FILES)

include ../../shlr/qjs/deps.mk
include ../rules.mk
