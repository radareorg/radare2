NAME=r_anal
DEPS=r_util r_lib r_reg r_syscall r_diff # r_core (commented as it would be recursive)
CFLAGS+=-DCORELIB -Iarch

include ../config.mk

LDFLAGS+=${BN_LIBS}

foo: pre libr_anal.${EXT_SO} libr_anal.${EXT_AR} plugins

include ${STATIC_ANAL_PLUGINS}
STATIC_OBJS=$(subst ../ar,p/../ar,$(subst anal_,p/anal_,$(STATIC_OBJ)))
OBJLIBS=meta.o reflines.o ref.o op.o fcn.o bb.o var.o anal.o cond.o value.o cc.o diff.o type.o fcnstore.o
OBJ=${STATIC_OBJS} ${OBJLIBS}

pre:
	@if [ ! -e libr_anal.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

plugins:
	@${MAKE} -C p all

include ../rules.mk
