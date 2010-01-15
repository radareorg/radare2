include ../../config.mk

CFLAGS+=-Ilibgdbwrap/include
ifeq (${OSTYPE},windows)
LDFLAGS+=-lwsock32
endif
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif

OBJ_GDB=debug_gdb.o libgdbwrap/gdbwrapper.c

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=debug_gdb.${EXT_SO}

ALL_TARGETS+=${TARGET_GDB}

${TARGET_GDB}: ${OBJ_GDB}
	${CC} ${OBJ_GDB} ${CFLAGS} ${LDFLAGS} -o ${TARGET_GDB}
