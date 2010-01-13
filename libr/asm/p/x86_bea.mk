OBJ_X86_BEA=asm_x86_bea.o
OBJ_X86_BEA+=../arch/x86/bea/BeaEngine.o

STATIC_OBJ+=${OBJ_X86_BEA}
TARGET_X86_BEA=asm_x86_bea.so

ALL_TARGETS+=${TARGET_X86_BEA}

${TARGET_X86_BEA}: ${OBJ_X86_BEA}
	${CC} ${CFLAGS} -o ${TARGET_X86_BEA} ${OBJ_X86_BEA}
	@#strip -s asm_x86_bea.so
