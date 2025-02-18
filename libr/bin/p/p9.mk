OBJ_P9=bin_p9.o ../format/p9/p9bin.o

STATIC_OBJ+=${OBJ_P9}
TARGET_P9=bin_p9.${EXT_SO}

ALL_TARGETS+=${TARGET_P9}

${TARGET_P9}: ${OBJ_P9}
	-${CC} $(call libname,bin_p9) ${CFLAGS} ${OBJ_P9}
