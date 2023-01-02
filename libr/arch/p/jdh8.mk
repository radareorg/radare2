OBJ_JDH8=p/jdh8/plugin.o

STATIC_OBJ+=${OBJ_JDH8}
TARGET_JDH8=arch_jdh8.${EXT_SO}

ALL_TARGETS+=${TARGET_JDH8}

${TARGET_JDH8}: ${OBJ_JDH8}
	${CC} $(call libname,arch_jdh8) ${LDFLAGS} ${CFLAGS} -o arch_jdh8.${EXT_SO} ${OBJ_JDH8}
