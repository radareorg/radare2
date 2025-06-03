OBJ_NULL=muta_null.o

STATIC_OBJ+=${OBJ_NULL}
TARGET_NULL=muta_null.${EXT_SO}

ALL_TARGETS+=${TARGET_NULL}

${TARGET_NULL}: ${OBJ_NULL}
	${CC} $(call libname,muta_null) ${LDFLAGS} ${CFLAGS} -o ${TARGET_NULL} ${OBJ_NULL}
