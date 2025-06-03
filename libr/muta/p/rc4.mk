OBJ_RC4=muta_rc4.o

STATIC_OBJ+=${OBJ_RC4}
TARGET_RC4=muta_rc4.${EXT_SO}

ALL_TARGETS+=${TARGET_RC4}

${TARGET_RC4}: ${OBJ_RC4}
	${CC} $(call libname,muta_rc4) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RC4} ${OBJ_RC4}
