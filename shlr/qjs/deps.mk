include ../../libr/config.mk
# include $(SHLR)/qjs/config.mk
LINK_QJS_ARCHIVE=0
QJS_LIBC=0
QJS_CFLAGS+=-Dutf8_encode=utf8_encode_r2

ifeq ($(OSTYPE),android)
# Android's clang/lld can leave references to QuickJS cutils static inlines.
QJS_CFLAGS+=-Dinline= -Wno-unused-function
endif

ifeq ($(LINK_QJS_ARCHIVE),1)
QJSFILES=$(QJS_NAME)/libquickjs.a
else
QJSFILES+=quickjs.c
QJSFILES+=cutils.c
QJSFILES+=libregexp.c
QJSFILES+=libunicode.c
# https://github.com/quickjs-ng/quickjs/issues/17
# QJSFILES+=libbf.c
QJSFILES+=dtoa.c
ifeq ($(QJS_LIBC),1)
QJSFILES+=quickjs-libc.c
endif
endif

QJSOBJS=$(subst .c,.o,$(QJSFILES))
QJS_FILES=$(addprefix $(SPRJ)/qjs/,$(QJSFILES))
QJS_OBJS=$(addprefix $(SPRJ)/qjs/,$(QJSOBJS))
CFLAGS+=-I$(SPRJ)/qjs/
