OBJ_RAR=bin_rar.o

STATIC_OBJ+=${OBJ_RAR}
TARGET_RAR=bin_rar.${EXT_SO}

ALL_TARGETS+=${TARGET_RAR}

${TARGET_RAR}: ${OBJ_RAR}
	${CC} $(call libname,bin_rar) ${CFLAGS} ${OBJ_RAR}
