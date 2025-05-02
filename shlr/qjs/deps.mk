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
# QJSFILES+=libbf.c
QJSFILES+=xsum.c
ifeq ($(QJS_LIBC),1)
QJSFILES+=quickjs-libc.c
endif
endif

QJSOBJS=$(subst .c,.o,$(QJSFILES))
QJS_FILES=$(addprefix $(SPRJ)/qjs/,$(QJSFILES))
QJS_OBJS=$(addprefix $(SPRJ)/qjs/,$(QJSOBJS))
CFLAGS+=-I$(SPRJ)/qjs/
