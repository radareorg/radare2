OBJ_NULL=debug_null.o

STATIC_OBJ+=${OBJ_NULL}
TARGET_NULL=debug_null.${EXT_SO}

ALL_TARGETS+=${TARGET_NULL}

${TARGET_NULL}: ${OBJ_NULL}
	${CC} $(call libname,debug_null) ${OBJ_NULL} ${CFLAGS} ${LDFLAGS} -o ${TARGET_NULL}
