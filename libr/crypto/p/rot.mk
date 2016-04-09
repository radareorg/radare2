OBJ_ROT=crypto_rot.o

STATIC_OBJ+=${OBJ_ROT}
TARGET_ROT=crypto_rot.${EXT_SO}

ALL_TARGETS+=${TARGET_ROT}

${TARGET_ROT}: ${OBJ_ROT}
	${CC} $(call libname,crypto_rot) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ROT} ${OBJ_ROT}
