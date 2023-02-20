include ../../libr/config.mk
# include $(SHLR)/qjs/config.mk
LINK_QJS_ARCHIVE=0
QJS_STACK_CHECK=1
QJS_BIGNUM=1
QJS_LIBC=0

ifeq ($(LINK_QJS_ARCHIVE),1)
QJSFILES=$(QJS_NAME)/libquickjs.a
else
QJSFILES+=quickjs.c
QJSFILES+=cutils.c
QJSFILES+=libregexp.c
QJSFILES+=libunicode.c
ifeq ($(QJS_LIBC),1)
QJSFILES+=quickjs-libc.c
endif
ifeq ($(QJS_BIGNUM),1)
QJSFILES+=libbf.c
endif
endif

QJSOBJS=$(subst .c,.o,$(QJSFILES))
QJS_FILES=$(addprefix $(SHLR)/qjs/src/,$(QJSFILES))
QJS_OBJS=$(addprefix $(SHLR)/qjs/src/,$(QJSOBJS))
CFLAGS+=-I$(SHLR)/qjs/src
ifeq ($(QJS_BIGNUM),1)
CFLAGS+=-DCONFIG_BIGNUM=$(QJS_BIGNUM)
endif
ifeq ($(QJS_STACK_CHECK),1)
CFLAGS+=-DCONFIG_STACK_CHECK=y
endif
