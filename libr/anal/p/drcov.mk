OBJ_DRCOV=anal_drcov.o

STATIC_OBJ+=${OBJ_DRCOV}
TARGET_DRCOV=anal_drcov.${EXT_SO}

ALL_TARGETS+=${TARGET_DRCOV}

${TARGET_DRCOV}: ${OBJ_DRCOV}
	${CC} $(call libname,anal_drcov) ${LDFLAGS} \
		${CFLAGS} -o anal_drcov.${EXT_SO} ${OBJ_DRCOV}
