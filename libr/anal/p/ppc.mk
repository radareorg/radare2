OBJ_PPC=anal_ppc.o

STATIC_OBJ+=${OBJ_PPC}
TARGET_PPC=anal_ppc.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC}

${TARGET_PPC}: ${OBJ_PPC}
	${CC} -shared ${CFLAGS} -o anal_ppc.${EXT_SO} ${OBJ_PPC}
	@#strip -s anal_ppc.${EXT_SO}
