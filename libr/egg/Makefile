NAME=r_egg
DEPS=r_util r_asm r_syscall r_db

include ../config.mk

#OBJS+=p/x86_osx_binsh.o
OBJS=egg.o lang.o
OBJS+=emit_x86.o
OBJS+=emit_arm.o
OBJS+=emit_x64.o
OBJS+=emit_trace.o

foo:
	for a in ${LIBSO} ${LIBAR} all ; do ${MAKE} $$a ; done

P=p/
include ${STATIC_EGG_PLUGINS}
OBJS+=$(subst ..,p/..,$(subst egg_,p/egg_,$(STATIC_OBJ)))

#plugins plugins:
# Do not build plugins. all are static @cd p && ${MAKE} all

include ../rules.mk
