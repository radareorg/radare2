OBJ_MD4=muta_md4.o

STATIC_OBJ+=${OBJ_MD4}
TARGET_MD4=muta_md4.${EXT_SO}

ALL_TARGETS+=${TARGET_MD4}

${TARGET_MD4}: ${OBJ_MD4}
	$(CC) $(call libname,muta_md4) ${LDFLAGS} ${CFLAGS} -o ${TARGET_MD4} ${OBJ_MD4}
