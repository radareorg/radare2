OBJ_XOR=muta_xor.o

STATIC_OBJ+=${OBJ_XOR}
TARGET_XOR=muta_xor.${EXT_SO}

ALL_TARGETS+=${TARGET_XOR}

${TARGET_XOR}: ${OBJ_XOR}
	${CC} $(call libname,muta_xor) ${LDFLAGS} ${CFLAGS} -o ${TARGET_XOR} ${OBJ_XOR}
