OBJ_IO=debug_io.o

STATIC_OBJ+=${OBJ_IO}
TARGET_IO=debug_io.${EXT_SO}

ALL_TARGETS+=${TARGET_IO}

${TARGET_IO}: ${OBJ_IO}
	${CC} $(call libname,debug_io) ${OBJ_IO} ${CFLAGS} ${LDFLAGS} -o ${TARGET_IO}
