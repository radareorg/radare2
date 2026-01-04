OBJ_MD5=muta_md5.o

STATIC_OBJ+=${OBJ_MD5}
TARGET_MD5=muta_md5.${EXT_SO}

ALL_TARGETS+=${TARGET_MD5}

${TARGET_MD5}: ${OBJ_MD5}
	$(CC) $(call libname,muta_md5) ${LDFLAGS} ${CFLAGS} -o ${TARGET_MD5} ${OBJ_MD5}
