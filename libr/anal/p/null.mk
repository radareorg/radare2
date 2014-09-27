OBJ_NULL=anal_null.o

STATIC_OBJ+=${OBJ_NULL}
TARGET_NULL=anal_null.${EXT_SO}

ALL_TARGETS+=${TARGET_NULL}

${TARGET_NULL}: ${OBJ_NULL}
	${CC} $(call libname,anal_null) ${LDFLAGS} \
		${CFLAGS} -o anal_null.${EXT_SO} ${OBJ_NULL}
