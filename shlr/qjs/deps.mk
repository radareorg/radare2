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
QJSFILES+=unicode_gen.c
QJSFILES+=libunicode.c
ifeq ($(QJS_LIBC),1)
QJSFILES+=quickjs-libc.c
endif
endif

QJS_FILES=$(addprefix $(SHLR)/qjs/src/,$(QJSFILES))
QJS_OBJS=$(subst .c,.o,$(QJS_FILES))
CFLAGS+=-I$(SHLR)/qjs/src
