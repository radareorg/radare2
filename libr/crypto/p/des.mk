OBJ_DES=crypto_des.o

STATIC_OBJ+=${OBJ_DES}
TARGET_DES=crypto_des.${EXT_SO}

ALL_TARGETS+=${TARGET_DES}

${TARGET_DES}: ${OBJ_DES}
	${CC} $(call libname,crypto_des) ${LDFLAGS} ${CFLAGS} -o ${TARGET_DES} ${OBJ_DES}
