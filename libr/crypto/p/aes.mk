OBJ_AES=crypto_aes.o crypto_aes_algo.o

STATIC_OBJ+=${OBJ_AES}
TARGET_AES=crypto_aes.${EXT_SO}

ALL_TARGETS+=${TARGET_AES}

${TARGET_AES}: ${OBJ_AES}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_AES} ${OBJ_AES}
