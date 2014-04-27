OBJ_MIPS=anal_mips.o

STATIC_OBJ+=${OBJ_MIPS}
TARGET_MIPS=anal_mips.${EXT_SO}

ALL_TARGETS+=${TARGET_MIPS}

${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} $(call libname,anal_mips) ${CFLAGS} -o anal_mips.${EXT_SO} ${OBJ_MIPS}
