OBJ_P9=fs_p9.o

STATIC_OBJ+=${OBJ_P9}
TARGET_P9=fs_p9.${EXT_SO}

ALL_TARGETS+=${TARGET_P9}

${TARGET_P9}: ${OBJ_P9}
	${CC} $(call libname,fs_p9) ${LDFLAGS} ${CFLAGS} -o ${TARGET_P9} ${OBJ_P9} ${EXTRA}
