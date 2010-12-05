NAME=r_anal
DEPS=r_util r_lib r_reg
CFLAGS+=-DCORELIB -Iarch

include ../config.mk

LDFLAGS+=${BN_LIBS}

foo: pre libr_anal.${EXT_SO} libr_anal.${EXT_AR} plugins

include ${STATIC_ANAL_PLUGINS}
#STATIC_OBJS=$(subst ..,p/..,$(subst anal_,p/anal_,$(STATIC_OBJ)))
STATIC_OBJS=$(subst ../ar,p/../ar,$(subst anal_,p/anal_,$(STATIC_OBJ)))
OBJLIBS=ctx.o meta.o reflines.o ref.o aop.o fcn.o bb.o var.o anal.o cond.o value.o call.o diff.o
OBJ=${STATIC_OBJS} ${OBJLIBS}

pre:
	if [ ! -e libr_anal.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	cd p && ${MAKE} all

include ../rules.mk
