OBJ_DIS=bin_dis.o

STATIC_OBJ+=${OBJ_DIS}
TARGET_DIS=bin_dis.${EXT_SO}

ALL_TARGETS+=${TARGET_DIS}

${TARGET_DIS}: ${OBJ_DIS}
	-${CC} $(call libname,bin_dis) ${CFLAGS} ${OBJ_DIS}
