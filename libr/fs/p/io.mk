OBJ_IO=fs_io.o

STATIC_OBJ+=${OBJ_IO}
TARGET_IO=fs_io.${EXT_SO}

ALL_TARGETS+=${TARGET_IO}

${TARGET_IO}: ${OBJ_IO}
	${CC} $(call libname,fs_io) ${LDFLAGS} ${CFLAGS} -o ${TARGET_IO} ${OBJ_IO} ${EXTRA}
