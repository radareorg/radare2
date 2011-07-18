OBJ_PPC=anal_ppc.o

STATIC_OBJ+=${OBJ_PPC}
TARGET_PPC=anal_ppc.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC}

${TARGET_PPC}: ${OBJ_PPC}
	${CC} $(call libname,anal_ppc) ${CFLAGS} -o anal_ppc.${EXT_SO} ${OBJ_PPC}
