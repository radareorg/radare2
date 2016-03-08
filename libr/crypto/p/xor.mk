OBJ_XOR=crypto_xor.o

STATIC_OBJ+=${OBJ_XOR}
TARGET_XOR=crypto_xor.${EXT_SO}

ALL_TARGETS+=${TARGET_XOR}

${TARGET_XOR}: ${OBJ_XOR}
	${CC} $(call libname,crypto_xor) ${LDFLAGS} ${CFLAGS} -o ${TARGET_XOR} ${OBJ_XOR}
