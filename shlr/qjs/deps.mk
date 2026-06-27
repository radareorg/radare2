include ../../libr/config.mk
# include $(SHLR)/qjs/config.mk
LINK_QJS_ARCHIVE=0
QJS_LIBC=0
QJS_CFLAGS+=-Dutf8_encode=utf8_encode_r2
# Build qjs without inline assembly. Its only inline asm is the 32-bit x86
# x87 FPU control-word macro in cutils.h, which on i386 (e.g. alpine-x86-32 /
# iSH) expands to a declaration right after a label and breaks the build (and
# the fnstcw/fldcw ops are unreliable under x86 emulators). No-op elsewhere.
QJS_CFLAGS+=-DJS_NO_INLINE_ASM

ifeq ($(OSTYPE),android)
# Android's clang/lld can leave references to QuickJS cutils static inlines.
QJS_CFLAGS+=-Dinline= -Wno-unused-function
endif

ifeq ($(LINK_QJS_ARCHIVE),1)
QJSFILES=$(QJS_NAME)/libquickjs.a
else
QJSFILES+=quickjs.c
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
