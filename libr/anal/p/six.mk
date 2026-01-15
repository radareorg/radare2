OBJ_SIX=anal_six.o
STATIC_OBJ+=${OBJ_SIX}
TARGET_SIX=anal_six.${EXT_SO}

ALL_TARGETS+=${TARGET_SIX}

${TARGET_SIX}: ${OBJ_SIX}
	${CC} $(call libname,anal_six) ${LDFLAGS} \
		${CFLAGS} -o anal_six.${EXT_SO} ${OBJ_SIX}
