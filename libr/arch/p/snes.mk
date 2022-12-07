OBJ_SNES=p/snes/plugin.o

STATIC_OBJ+=${OBJ_SNES}
TARGET_SNES=arch_snes.${EXT_SO}

ALL_TARGETS+=${TARGET_SNES}

${TARGET_SNES}: ${OBJ_SNES}
	${CC} $(call libname,arch_snes) ${LDFLAGS} ${CFLAGS} -o arch_snes.${EXT_SO} ${OBJ_SNES}
