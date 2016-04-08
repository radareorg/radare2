OBJ_SNES=anal_snes.o

STATIC_OBJ+=${OBJ_SNES}
TARGET_SNES=anal_snes.${EXT_SO}

ALL_TARGETS+=${TARGET_SNES}

${TARGET_SNES}: ${OBJ_SNES}
	${CC} $(call libname,anal_snes) ${LDFLAGS} ${CFLAGS} -o anal_snes.${EXT_SO} ${OBJ_SNES}
