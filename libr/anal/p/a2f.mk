OBJ_A2F=anal_a2f.o

STATIC_OBJ+=${OBJ_A2F}
TARGET_A2F=anal_a2f.${EXT_SO}

ALL_TARGETS+=${TARGET_A2F}

${TARGET_A2F}: ${OBJ_A2F}
	${CC} $(call libname,anal_a2f) ${LDFLAGS} \
		${CFLAGS} -o anal_a2f.${EXT_SO} ${OBJ_A2F}
