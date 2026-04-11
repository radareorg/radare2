OBJ_CALLARGS=anal_callargs.o

STATIC_OBJ+=${OBJ_CALLARGS}
TARGET_CALLARGS=anal_callargs.${EXT_SO}

ALL_TARGETS+=${TARGET_CALLARGS}

${TARGET_CALLARGS}: ${OBJ_CALLARGS}
	${CC} $(call libname,anal_callargs) ${LDFLAGS} \
		${CFLAGS} -o anal_callargs.${EXT_SO} ${OBJ_CALLARGS}
