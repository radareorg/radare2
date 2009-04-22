OBJ_PSOSVM=asm_psosvm.o
OBJ_PSOSVM+=../arch/psosvm/vmas/vmas.o

STATIC_OBJ+=${OBJ_PSOSVM}
TARGET_PSOSVM=asm_psosvm.so

ALL_TARGETS+=${TARGET_PSOSVM}

${TARGET_PSOSVM}: ${OBJ_PSOSVM}
	${CC} ${CFLAGS} -o asm_psosvm.so ${OBJ_PSOSVM}
	@#strip -s asm_psosvm.so
