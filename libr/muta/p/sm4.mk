OBJ_SM4=muta_sm4.o p/algo/sm4.o

STATIC_OBJ+=${OBJ_SM4}
TARGET_SM4=muta_sm4.${EXT_SO}

ALL_TARGETS+=${TARGET_SM4}

${TARGET_SM4}: ${OBJ_SM4}
	${CC} ${call libname,muta_sm4} ${LDFLAGS} ${CFLAGS} -o ${TARGET_SM4} ${OBJ_SM4}
