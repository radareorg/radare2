OBJ_JAVA=anal_java.o

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=anal_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,anal_java) ${LDFLAGS} \
		${CFLAGS} -o anal_java.${EXT_SO} ${OBJ_JAVA}
