OBJ_COSMAC=p/cosmac/plugin.o

STATIC_OBJ+=${OBJ_COSMAC}
TARGET_COSMAC=arch_cosmac.${EXT_SO}

ALL_TARGETS+=${TARGET_COSMAC}

${TARGET_COSMAC}: ${OBJ_COSMAC}
	${CC} $(call libname,arch_cosmac) ${CFLAGS} -o arch_i4004.${EXT_SO} ${OBJ_COSMAC}
