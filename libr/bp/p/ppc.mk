OBJ_PPC=bp_ppc.o

STATIC_OBJ+=${OBJ_PPC}
TARGET_PPC=bp_ppc.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC}

${TARGET_PPC}: ${OBJ_PPC}
	${CC} $(call libname,bp_ppc) ${CFLAGS} -o ${TARGET_PPC} ${OBJ_PPC}
