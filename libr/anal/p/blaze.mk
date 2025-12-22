OBJ_BLAZE=anal_blaze.o

STATIC_OBJ+=${OBJ_BLAZE}
TARGET_BLAZE=anal_blaze.${EXT_SO}

ALL_TARGETS+=${TARGET_BLAZE}

${TARGET_BLAZE}: ${OBJ_BLAZE}
	${CC} $(call libname,anal_blaze) ${LDFLAGS} \
		${CFLAGS} -o anal_blaze.${EXT_SO} ${OBJ_BLAZE}
