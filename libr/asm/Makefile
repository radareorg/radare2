NAME=r_asm
DEPS=r_lib r_util
CFLAGS+=-DCORELIB -Iarch/include -Iarch

include ../config.mk

foo: pre ${LIBSO} ${LIBAR} plugins

include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJ=${STATIC_OBJS} asm.o code.o

pre:
	@if [ ! -e libr_asm.${EXT_SO} ]; then if [ ! -e libr_asm.${EXT_AR} ]; then rm -f ${STATIC_OBJS} ; fi ; fi

re:
	rm -f asm.o libr_asm.so
	${MAKE}
	sudo ${MAKE} install

plugins:
	cd p && ${MAKE} all

include ../rules.mk
