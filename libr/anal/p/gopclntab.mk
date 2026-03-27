OBJ_GOPCLNTAB=anal_gopclntab.o

STATIC_OBJ+=${OBJ_GOPCLNTAB}
TARGET_GOPCLNTAB=anal_gopclntab.${EXT_SO}

ALL_TARGETS+=${TARGET_GOPCLNTAB}

${TARGET_GOPCLNTAB}: ${OBJ_GOPCLNTAB}
	${CC} $(call libname,anal_gopclntab) ${LDFLAGS} \
		${CFLAGS} -o anal_gopclntab.${EXT_SO} ${OBJ_GOPCLNTAB}
