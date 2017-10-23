OBJ_R2=fs_r2.o

STATIC_OBJ+=${OBJ_R2}
TARGET_R2=fs_r2.${EXT_SO}

ALL_TARGETS+=${TARGET_R2}

${TARGET_R2}: ${OBJ_R2}
	${CC} $(call libname,fs_r2) ${LDFLAGS} ${CFLAGS} -o ${TARGET_R2} ${OBJ_R2} ${EXTRA}
