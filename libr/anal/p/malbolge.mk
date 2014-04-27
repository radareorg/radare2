OBJ_MALBOLGE=anal_malbolge.o

STATIC_OBJ+=${OBJ_MALBOLGE}
TARGET_MALBOLGE=anal_malbolge.${EXT_SO}

ALL_TARGETS+=${TARGET_MALBOLGE}

${TARGET_MALBOLGE}: ${OBJ_MALBOLGE}
	${CC} $(call libname,anal_malbolge) ${LDFLAGS} ${CFLAGS} -o anal_malbolge.${EXT_SO} ${OBJ_MALBOLGE}
