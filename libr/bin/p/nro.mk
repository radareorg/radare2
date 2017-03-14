OBJ_NRO=bin_nro.o

STATIC_OBJ+=${OBJ_NRO}
TARGET_NRO=bin_nro.${EXT_SO}

ALL_TARGETS+=${TARGET_NRO}

${TARGET_NRO}: ${OBJ_NRO}
	-${CC} $(call libname,bin_nro) ${CFLAGS} ${OBJ_NRO}
