OBJ_PPC=anal_ppc_gnu.o

STATIC_OBJ+=${OBJ_PPC}
TARGET_PPC=anal_ppc_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC}

${TARGET_PPC}: ${OBJ_PPC}
	${CC} $(call libname,anal_ppc_gnu) ${CFLAGS} \
		-o anal_ppc_gnu.${EXT_SO} ${OBJ_PPC}
