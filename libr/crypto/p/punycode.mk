OBJ_PUNY=crypto_punycode.o

STATIC_OBJ+=${OBJ_PUNY}
TARGET_PUNY=crypto_punycode.${EXT_SO}

ALL_TARGETS+=${TARGET_PUNY}

${TARGET_PUNY}: ${OBJ_PUNY}
	${CC} $(call libname,crypto_punycode) ${LDFLAGS} ${CFLAGS} -o ${TARGET_PUNY} ${OBJ_PUNY}
