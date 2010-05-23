OBJ_PSOSVM=asm_psosvm.o
OBJ_PSOSVM+=../arch/psosvm/vmas/vmas.o

STATIC_OBJ+=${OBJ_PSOSVM}
TARGET_PSOSVM=asm_psosvm.${EXT_SO}

ALL_TARGETS+=${TARGET_PSOSVM}

${TARGET_PSOSVM}: ${OBJ_PSOSVM}
	${CC} ${LDFLAGS} ${CFLAGS} -o asm_psosvm.${EXT_SO} ${OBJ_PSOSVM}
