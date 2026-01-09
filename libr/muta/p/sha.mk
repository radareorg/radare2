OBJ_SHA=muta_sha.o

STATIC_OBJ+=${OBJ_SHA}
TARGET_SHA=muta_sha.${EXT_SO}

ALL_TARGETS+=${TARGET_SHA}

${TARGET_SHA}: ${OBJ_SHA}
	$(CC) $(call libname,muta_sha) ${LDFLAGS} ${CFLAGS} -o ${TARGET_SHA} ${OBJ_SHA}
