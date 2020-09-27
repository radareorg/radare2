include ../config.mk

NAME=r_egg
R2DEPS=r_asm r_syscall r_util r_parse r_reg r_lang
R2DEPS+=r_flag r_cons

OBJS=egg.o egg_lang.o
OBJS+=emit_x86.o
OBJS+=emit_arm.o
OBJS+=emit_x64.o
OBJS+=emit_trace.o
OBJS+=egg_Cfile.o

all: ${LIBSO} ${LIBAR}

P=p/
include ${STATIC_EGG_PLUGINS}
include $(STOP)/java/deps.mk

ifneq (${STATIC_OBJ},)
OBJS+=$(subst ..,${P}..,$(subst egg_,${P}egg_,$(STATIC_OBJ)))
endif

include ../rules.mk
