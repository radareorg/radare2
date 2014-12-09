OBJ_CRIS=anal_cris.o

STATIC_OBJ+=$(OBJ_CRIS)
TARGET_CRIS=anal_cris.${EXT_SO}

ALL_TARGETS+=${TARGET_CRIS}

${TARGET_CRIS}: ${OBJ_CRIS}
	${CC} ${CFLAGS} $(call libname,anal_cris) \
		-o anal_cris.${EXT_SO} ${OBJ_CRIS}
