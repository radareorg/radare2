OBJ_MZ=bin_mz.o

STATIC_OBJ+=${OBJ_MZ}
TARGET_MZ=bin_mz.${EXT_SO}

ALL_TARGETS+=${TARGET_MZ}

${TARGET_MZ}: ${OBJ_MZ}
	${CC} $(call libname,bin_mz) ${CFLAGS} ${OBJ_MZ}
