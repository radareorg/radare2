NAME=r_asm
DEPS=r_lib r_util
CFLAGS+=-DCORELIB -Iarch/include -Iarch

foo: pre ${LIBSO} ${LIBAR} plugins

include ../config.mk
include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJ=${STATIC_OBJS} asm.o

pre:
	@if [ ! -e libr_asm.so ]; then rm -f ${STATIC_OBJS} ; fi

re:
	rm -f asm.o libr_asm.so
	${MAKE}
	rm -f t/fastcall.o
	sudo ${MAKE} install
	cd t && ${MAKE}

plugins:
	cd p && ${MAKE} all

include ../rules.mk
