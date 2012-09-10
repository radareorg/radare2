include ../../global.mk

NAME=r_anal
EXTRA_CLEAN=clean2
DEPS=r_util r_db r_lib r_reg r_syscall r_diff
# r_core (commented as it would be recursive)
CFLAGS+=-DCORELIB -Iarch -I$(TOP)/shlr

include $(LTOP)/config.mk

LDFLAGS+=${BN_LIBS}

foo:
	for a in pre libr_anal.${EXT_SO} libr_anal.${EXT_AR} plugins ; do ${MAKE} $$a ; done

include ${STATIC_ANAL_PLUGINS}
STATIC_OBJS=$(addprefix $(LTOP)/anal/p/,$(STATIC_OBJ))
OBJLIBS=meta.o reflines.o ref.o op.o fcn.o bb.o var.o anal.o cond.o value.o cc.o diff.o type.o fcnstore.o

CPARSE_OBJS=cparse/cparse.o cparse/lex.yy.o cparse/tree.o cparse/gen.o cparse/error.o cparse/symset.o cparse/pplex.o cparse/exptree.o cparse/pp.o

OBJ=${STATIC_OBJS} ${OBJLIBS} ${CPARSE_OBJS}

pre:
	@cd cparse && ${MAKE} all
	@cd $(TOP)/shlr && ${MAKE}

#@if [ ! -e libr_anal.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

clean2:
	@cd cparse && ${MAKE} clean

plugins:
	@${MAKE} -C p all

include $(LTOP)/rules.mk
