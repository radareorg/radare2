include ../../libr/config.mk
# include $(SHLR)/qjs/config.mk
LINK_QJS_ARCHIVE=0
QJS_LIBC=0

ifeq ($(LINK_QJS_ARCHIVE),1)
QJSFILES=$(QJS_NAME)/libquickjs.a
else
QJSFILES+=quickjs.c
QJSFILES+=cutils.c
QJSFILES+=libregexp.c
QJSFILES+=libunicode.c
# https://github.com/quickjs-ng/quickjs/issues/17
QJSFILES+=libbf.c
ifeq ($(QJS_LIBC),1)
QJSFILES+=quickjs-libc.c
endif
endif

QJSOBJS=$(subst .c,.o,$(QJSFILES))
QJS_FILES=$(addprefix $(SHLR)/qjs/src/,$(QJSFILES))
QJS_OBJS=$(addprefix $(SHLR)/qjs/src/,$(QJSOBJS))
CFLAGS+=-I$(SHLR)/qjs/src
