NAME=r_egg
DEPS=r_util r_asm r_syscall r_db

include ../config.mk

#OBJ+=p/x86_osx_binsh.o
OBJ=egg.o lang.o
OBJ+=emit_x86.o
OBJ+=emit_arm.o
OBJ+=emit_x64.o
OBJ+=emit_trace.o

include ${STATIC_EGG_PLUGINS}
OBJ+=$(subst ..,p/..,$(subst egg_,p/egg_,$(STATIC_OBJ)))

foo: ${LIBSO} ${LIBAR} 

#plugins plugins:
# Do not build plugins. all are static @cd p && ${MAKE} all

include ../rules.mk
