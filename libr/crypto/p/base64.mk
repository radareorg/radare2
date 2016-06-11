OBJ_B64=crypto_base64.o

STATIC_OBJ+=${OBJ_B64}
TARGET_B64=crypto_base64.${EXT_SO}

ALL_TARGETS+=${TARGET_B64}

${TARGET_B64}: ${OBJ_B64}
	${CC} $(call libname,crypto_base64) ${LDFLAGS} ${CFLAGS} -o ${TARGET_B64} ${OBJ_B64}
