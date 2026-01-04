OBJ_SHA1=muta_sha1.o

STATIC_OBJ+=${OBJ_SHA1}
TARGET_SHA1=muta_sha1.${EXT_SO}

ALL_TARGETS+=${TARGET_SHA1}

${TARGET_SHA1}: ${OBJ_SHA1}
	$(CC) $(call libname,muta_sha1) ${LDFLAGS} ${CFLAGS} -o ${TARGET_SHA1} ${OBJ_SHA1}
