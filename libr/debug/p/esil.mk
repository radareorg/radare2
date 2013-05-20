OBJ_ESIL=debug_esil.o

STATIC_OBJ+=${OBJ_ESIL}
TARGET_ESIL=debug_esil.${EXT_SO}

ALL_TARGETS+=${TARGET_ESIL}

${TARGET_ESIL}: ${OBJ_ESIL}
	${CC} $(call libname,debug_esil) ${OBJ_ESIL} ${CFLAGS} ${LDFLAGS} -o ${TARGET_ESIL}
