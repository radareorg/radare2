OBJ_NULL=bp_null.o

STATIC_OBJ+=${OBJ_NULL}
TARGET_NULL=bp_null.${EXT_SO}

ALL_TARGETS+=${TARGET_NULL}

${TARGET_NULL}: ${OBJ_NULL}
	${CC_LIB} $(call libname,bp_null) ${CFLAGS} -o ${TARGET_NULL} ${OBJ_NULL}
