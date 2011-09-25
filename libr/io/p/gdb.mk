OBJ_GDB=io_gdb.o

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=io_gdb.${EXT_SO}
ALL_TARGETS+=${TARGET_GDB}
# /p
CFLAGS+=-I../debug/p/libgdbwrap/
CFLAGS+=-I../debug/p/libgdbwrap/include
# /
CFLAGS+=-I../../debug/p/libgdbwrap/
CFLAGS+=-I../../debug/p/libgdbwrap/include
#GDBWRAPFILES=../../debug/p/libgdbwrap/gdbwrapper.c

# copypasted from socket/Makefile
# on solaris only
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif
# windows
ifeq (${OSTYPE},windows)
LDFLAGS=-lwsock32
endif
ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/libr_socket.a
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS=-L../../socket -lr_socket
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

# TODO : link against gdbwrapper
${TARGET_GDB}: ${OBJ_GDB}
	${CC_LIB} ${TARGET_GDB} $(call libname,io_gdb) ${OBJ_GDB} ${CFLAGS} ${LDFLAGS} \
		${GDBWRAPFILES} ${LINKFLAGS} ${LDFLAGS_LIB}
