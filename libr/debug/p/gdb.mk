#include ../../config.mk
#BINDEPS=r_reg r_bp r_util r_io r_anal

CFLAGS+=-Ip/libgdbwrap/include
ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

LDFLAGS+=-L../../util -lr_util
LDFLAGS+=-L../../anal -lr_anal
LDFLAGS+=-L../../reg -lr_reg
LDFLAGS+=-L../../bp -lr_bp
LDFLAGS+=-L../../io -lr_io

OBJ_GDB=debug_gdb.o 
#libgdbwrap/gdbwrapper.o

#libgdbwrap/gdbwrapper.o:
#	${CC} -c ${CFLAGS} ${LDFLAGS} -o p/libgdbwrap/gdbwrapper.o p/libgdbwrap/gdbwrapper.c

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=debug_gdb.${EXT_SO}

ALL_TARGETS+=${TARGET_GDB}

${TARGET_GDB}: ${OBJ_GDB}
	${CC_LIB} $(call libname,debug_gdb) ${OBJ_GDB} ${CFLAGS} ${LDFLAGS}
