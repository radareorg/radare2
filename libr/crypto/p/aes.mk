OBJ_AES=crypto_aes.o crypto_aes_algo.o

STATIC_OBJ+=${OBJ_AES}
TARGET_AES=crypto_aes.so

ALL_TARGETS+=${TARGET_AES}

${TARGET_AES}: ${OBJ_AES}
	${CC} ${CFLAGS} -o ${TARGET_AES} ${OBJ_AES}
