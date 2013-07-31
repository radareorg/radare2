include ../config.mk

NAME=r_anal
DEPS=r_util r_db r_lib r_reg r_syscall r_diff r_db
# r_core (commented as it would be recursive)
CFLAGS*=HAVE_CPARSE=$(HAVE_CPARSE)
CFLAGS+=-DCORELIB -Iarch -I$(TOP)/shlr

LDFLAGS+=${BN_LIBS}

.PHONY: pre libs ${EXTRA_CLEAN}

all: plugins

plugins: libr_anal.${EXT_SO} libr_anal.${EXT_AR}
	@${MAKE} -C p all

libr_anal.${EXT_SO} libr_anal.${EXT_AR}: pre

include ${STATIC_ANAL_PLUGINS}
STATIC_OBJS=$(addprefix $(LTOP)/anal/p/,$(STATIC_OBJ))
OBJLIBS=meta.o reflines.o ref.o op.o fcn.o bb.o var.o
OBJLIBS+=cond.o value.o cc.o diff.o types.o fcnstore.o
OBJLIBS+=hint.o vm.o anal.o data.o xrefs.o esil.o

OBJS=${STATIC_OBJS} ${OBJLIBS} ${CPARSE_OBJS}

pre:
	@cd $(TOP)/shlr && ${MAKE}

include $(LTOP)/rules.mk
