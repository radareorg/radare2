OBJ_PATH=anal_path.o

STATIC_OBJ+=${OBJ_PATH}
TARGET_PATH=anal_path.${EXT_SO}

ALL_TARGETS+=${TARGET_PATH}

${TARGET_PATH}: ${OBJ_PATH}
	${CC} $(call libname,anal_path) ${LDFLAGS} \
		${CFLAGS} -o anal_path.${EXT_SO} ${OBJ_PATH}

