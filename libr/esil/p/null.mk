OBJ_ESIL_NULL=esil_null.o

STATIC_OBJ+=${OBJ_ESIL_NULL}
TARGET_ESIL_NULL=esil_null.${EXT_SO}

ALL_TARGETS+=${TARGET_ESIL_NULL}

${TARGET_ESIL_NULL}: ${OBJ_ESIL_NULL}
	${CC} $(call libname,esil_null) ${LDFLAGS} ${CFLAGS} -o esil_null.${EXT_SO} ${OBJ_ESIL_NULL}
