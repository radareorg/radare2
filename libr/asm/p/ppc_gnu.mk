OBJ_PPC=asm_ppc_gnu.o
OBJ_PPC+=../arch/ppc/gnu/ppc-dis.o
OBJ_PPC+=../arch/ppc/gnu/ppc-opc.o

STATIC_OBJ+=${OBJ_PPC}
TARGET_PPC=asm_ppc_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC}

${TARGET_PPC}: ${OBJ_PPC}
	${CC} $(call libname,asm_ppc) ${LDFLAGS} ${CFLAGS} -o asm_ppc_gnu.${EXT_SO} ${OBJ_PPC}
