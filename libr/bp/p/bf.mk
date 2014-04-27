OBJ_BF=bp_bf.o

STATIC_OBJ+=${OBJ_BF}
TARGET_BF=bp_bf.${EXT_SO}

ALL_TARGETS+=${TARGET_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC_LIB} $(call libname,bp_bf) ${CFLAGS} -o ${TARGET_BF} ${OBJ_BF}
