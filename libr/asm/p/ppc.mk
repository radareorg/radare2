OBJ_PPC=asm_ppc.o
OBJ_PPC+=../arch/ppc/ppc_disasm/ppc_disasm.o

STATIC_OBJ+=${OBJ_PPC}
TARGET_PPC=asm_ppc.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC}

${TARGET_PPC}: ${OBJ_PPC}
	${CC} ${CFLAGS} -o asm_ppc.${EXT_SO} ${OBJ_PPC}
