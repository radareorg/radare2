NAME=r_asm
DEPS=r_lib r_util r_cmd r_flags

foo: pre libr_asm.so plugins

CFLAGS+=-DCORELIB -Iarch/include -Iarch
include ../config.mk
include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJ=asm.o ${STATIC_OBJS}

pre:
	if [ ! -e libr_asm.so ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
