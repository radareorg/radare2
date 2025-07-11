OBJ_TCC=anal_tcc.o

STATIC_OBJ+=${OBJ_TCC}
TARGET_TCC=anal_tcc.${EXT_SO}

ALL_TARGETS+=${TARGET_TCC}

${TARGET_TCC}: ${OBJ_TCC}
	${CC} $(call libname,anal_tcc) ${LDFLAGS} \
		${CFLAGS} -o anal_tcc.${EXT_SO} ${OBJ_TCC}
