OBJ_TMP=fs_tmp.o

STATIC_OBJ+=${OBJ_TMP}
TARGET_TMP=fs_tmp.${EXT_SO}

ALL_TARGETS+=${TARGET_TMP}

${TARGET_TMP}: ${OBJ_TMP}
	${CC} $(call libname,fs_tmp) ${LDFLAGS} ${CFLAGS} -o ${TARGET_TMP} ${OBJ_TMP} ${EXTRA}
