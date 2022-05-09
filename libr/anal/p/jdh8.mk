OBJ_JDH8=anal_jdh8.o

STATIC_OBJ+=${OBJ_JDH8}
TARGET_JDH8=anal_jdh8.${EXT_SO}

ALL_TARGETS+=${TARGET_JDH8}

${TARGET_JDH8}: ${OBJ_JDH8}
	${CC} $(call libname,anal_jdh8) ${LDFLAGS} ${CFLAGS} -o anal_jdh8.${EXT_SO} ${OBJ_JDH8}
