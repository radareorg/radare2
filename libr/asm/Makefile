include ../../global.mk

NAME=r_asm
DEPS=r_util r_parse r_db r_syscall
CFLAGS+=-DCORELIB -Iarch/include -Iarch -I../../shlr

include $(TOP)/libr/config.mk
include ../db/build.mk

.PHONY: all plugins

all: plugins

plugins: ${LIBSO} ${LIBAR}
	@cd d && ${MAKE}
	@cd p && ${MAKE} all

include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} asm.o code.o
# hack to b
OBJS+=${SHARED2_OBJ}

include $(TOP)/libr/rules.mk
