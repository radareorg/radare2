OBJ_RC6=crypto_rc6.o

STATIC_OBJ+=${OBJ_RC6}
TARGET_RC6=crypto_rc6.${EXT_SO}

ALL_TARGETS+=${TARGET_RC6}

${TARGET_RC6}: ${OBJ_RC6}
	${CC} $(call libname,crypto_rc6) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RC6} ${OBJ_RC6}
