OBJ_STRHASH=crypto_strhash.o

STATIC_OBJ+=${OBJ_STRHASH}
TARGET_STRHASH=crypto_strhash.${EXT_SO}

ALL_TARGETS+=${TARGET_STRHASH}

${TARGET_STRHASH}: ${OBJ_STRHASH}
	$(CC) $(call libname,crypto_strhash) ${LDFLAGS} ${CFLAGS} -o ${TARGET_STRHASH} ${OBJ_STRHASH}
