include ../config.mk

NAME=r_egg
DEPS=r_util r_asm r_syscall r_db

OBJS=egg.o lang.o
OBJS+=emit_x86.o
OBJS+=emit_arm.o
OBJS+=emit_x64.o
OBJS+=emit_trace.o

all: ${LIBSO} ${LIBAR}

P=p/
include ${STATIC_EGG_PLUGINS}
OBJS+=$(subst ..,${P}..,$(subst egg_,${P}egg_,$(STATIC_OBJ)))

include ../rules.mk
