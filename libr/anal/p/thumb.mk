OBJ_THUMB=anal_thumb.o

STATIC_OBJ+=${OBJ_THUMB}
TARGET_THUMB=anal_thumb.${EXT_SO}

ALL_TARGETS+=${TARGET_THUMB}

${TARGET_THUMB}: ${OBJ_THUMB}
	${CC} $(call libname,anal_thumb) ${LDFLAGS} \
		${CFLAGS} -o anal_thumb.${EXT_SO} ${OBJ_THUMB}
