NAME=r_anal
DEPS=r_util r_lib
CFLAGS+=-DCORELIB -Iarch

include ../config.mk

foo: pre libr_anal.${EXT_SO} libr_anal.${EXT_AR} plugins

include ${STATIC_ANAL_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst anal_,p/anal_,$(STATIC_OBJ)))
OBJ=${STATIC_OBJS} ctx.o reflines.o ref.o aop.o fcn.o bb.o var.o anal.o

pre:
	if [ ! -e libr_anal.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
