OBJ_MALBOLGE=arch_malbolge.o

STATIC_OBJ+=${OBJ_MALBOLGE}
TARGET_MALBOLGE=arch_malbolge.${EXT_SO}

ALL_TARGETS+=${TARGET_MALBOLGE}

${TARGET_MALBOLGE}: ${OBJ_MALBOLGE}
	${CC} $(call libname,arch_malbolge) ${LDFLAGS} ${CFLAGS} -o arch_malbolge.${EXT_SO} ${OBJ_MALBOLGE}
