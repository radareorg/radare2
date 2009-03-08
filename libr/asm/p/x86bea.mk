OBJ_X86_BEA=asm_x86_bea.o
OBJ_X86_BEA+=../arch/x86/bea/BeaEngine.o

STATIC_OBJ+=${OBJ_X86_BEA}
TARGET_X86_BEA=asm_x86_bea.so

ALL_TARGETS+=${TARGET_X86_BEA}

#${TARGET_X86_BEA}: ${OBJ_X86_BEA}
asm_x86_bea.so: ${OBJ_X86_BEA}
	${CC} ${CFLAGS_IMP} -o asm_x86_bea.so \
		asm_x86_bea.c ../arch/x86/bea/BeaEngine.c
	@#strip -s asm_x86_bea.so
	${CC} ${CFLAGS} -o ${TARGET_X86_BEA} ${OBJ_X86_BEA}
	@#strip -s asm_x86.so
