OBJ_MIPS=asm_mips.o
# gnu mips-dis
OBJ_MIPS+=../arch/mips/gnu/mips-dis.o
OBJ_MIPS+=../arch/mips/gnu/mips16-opc.o
OBJ_MIPS+=../arch/mips/gnu/mips-opc.o

TARGET_MIPS=asm_mips.so
ALL_TARGETS+=${TARGET_MIPS}
STATIC_OBJ+=${OBJ_MIPS}

${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} ${CFLAGS} -o ${TARGET_MIPS} ${OBJ_MIPS}
	@#strip -s asm_x86.so
