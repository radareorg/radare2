OBJ_X86_BEA=anal_x86_bea.o
OBJ_X86_BEA+=../../asm/arch/x86/bea/BeaEngine.o

STATIC_OBJ+=${OBJ_X86_BEA}
TARGET_X86_BEA=anal_x86_bea.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_BEA}

${TARGET_X86_BEA}: ${OBJ_X86_BEA}
	${CC} ${CFLAGS} -o anal_x86_bea.${EXT_SO} ${OBJ_X86_BEA}
	@#strip -s anal_x86_bea.${EXT_SO}
