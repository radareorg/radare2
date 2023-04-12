OBJ_PPC=p/ppc/plugin_gnu.o
OBJ_PPC+=p/ppc/gnu/ppc-dis.o
OBJ_PPC+=p/ppc/gnu/ppc-opc.o

STATIC_OBJ+=${OBJ_PPC}
TARGET_PPC=arch_ppc_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC}

${TARGET_PPC}: ${OBJ_PPC}
	${CC} $(call libname,arch_ppc_gnu) ${CFLAGS} \
		-o arch_ppc_gnu.${EXT_SO} ${OBJ_PPC}
