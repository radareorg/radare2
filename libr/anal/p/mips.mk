OBJ_MIPS=anal_mips.o

STATIC_OBJ+=${OBJ_MIPS}
TARGET_MIPS=anal_mips.${EXT_SO}

ALL_TARGETS+=${TARGET_MIPS}

${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} ${CFLAGS} -o anal_mips.${EXT_SO} ${OBJ_MIPS}
	@#strip -s anal_mips.${EXT_SO}
