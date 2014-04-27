OBJ_MIPS=asm_mips.o
# gnu mips-dis
OBJ_MIPS+=../arch/mips/gnu/mips-dis.o
OBJ_MIPS+=../arch/mips/gnu/mips16-opc.o
OBJ_MIPS+=../arch/mips/gnu/mips-opc.o
OBJ_MIPS+=../arch/mips/mipsasm.o

TARGET_MIPS=asm_mips.${EXT_SO}
ALL_TARGETS+=${TARGET_MIPS}
STATIC_OBJ+=${OBJ_MIPS}

${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} $(call libname,asm_mips) ${LDFLAGS} ${CFLAGS} ${OBJ_MIPS}
