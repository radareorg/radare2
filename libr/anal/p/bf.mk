OBJ_BF=anal_bf.o

STATIC_OBJ+=${OBJ_BF}
TARGET_BF=anal_bf.${EXT_SO}

ALL_TARGETS+=${TARGET_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC} $(call libname,anal_bf) ${LDFLAGS} ${CFLAGS} -o anal_bf.${EXT_SO} ${OBJ_BF}
