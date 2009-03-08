OBJ_M68K=asm_m68k.o
OBJ_M68K+=../arch/m68k/m68k_disasm/m68k_disasm.o

STATIC_OBJ+=${OBJ_M68K}
TARGET_M68K=asm_m68k.so

ALL_TARGETS+=${TARGET_M68K}

${TARGET_M68K}: ${OBJ_M68K}
	${CC} ${CFLAGS} -o asm_m68k.so ${OBJ_M68K}
	@#strip -s asm_x86.so
