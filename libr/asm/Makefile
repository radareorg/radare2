include ../../global.mk

NAME=r_asm
DEPS=r_lib r_util r_parse r_db
CFLAGS+=-DCORELIB -Iarch/include -Iarch -I../../shlr

include $(TOP)/libr/config.mk

foo:
	@for a in pre ${LIBSO} ${LIBAR} plugins ; do ${MAKE} $$a ; done

include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} asm.o code.o

pre:
	@if [ ! -e libr_asm.${EXT_SO} ]; then if [ ! -e libr_asm.${EXT_AR} ]; then rm -f ${STATIC_OBJS} ; fi ; fi

re:
	rm -f asm.o libr_asm.so
	${MAKE}
	sudo ${MAKE} install

plugins:
	@cd d && ${MAKE}
	@cd p && ${MAKE} all

include $(TOP)/libr/rules.mk
