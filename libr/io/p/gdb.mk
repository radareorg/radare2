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

# copypasted from socket/Makefile
# on solaris only
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif
# windows
ifeq (${OSTYPE},windows)
LDFLAGS=-lwsock32
endif

# TODO : link against gdbwrapper
${TARGET_GDB}: ${OBJ_GDB}
	${CC} ${OBJ_GDB} ${CFLAGS} ${LDFLAGS} \
		-I../debug/p/libgdbwrap/ \
		-I../debug/p/libgdbwrap/include \
		-shared -o ${TARGET_GDB} ${LDFLAGS_LIB} \
		${LDFLAGS_LINKPATH}../../socket -L../../socket -lr_socket \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}.. -L.. -L../../lib -lr_lib -lr_io \
