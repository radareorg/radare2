include ../../../config-user.mk

CFLAGS+=-D__UNIX__=1
OBJ_GDB=debug_gdb.o libgdbwrap/gdbwrapper.o

STATIC_OBJ+=${OBJ_GDB}
TARGET_GDB=debug_gdb.so

ALL_TARGETS+=${TARGET_GDB}

${TARGET_GDB}: ${OBJ_GDB}
	${CC} ${CFLAGS} -o ${TARGET_GDB} ${OBJ_GDB}
