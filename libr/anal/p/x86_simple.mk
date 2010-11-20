OBJ_X86_SIMPLE=anal_x86_simple.o
OBJ_X86_SIMPLE+=../arch/x86/dislen/dislen.o

STATIC_OBJ+=${OBJ_X86_SIMPLE}
TARGET_X86_SIMPLE=anal_x86_simple.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_SIMPLE}

${TARGET_X86_SIMPLE}: ${OBJ_X86_SIMPLE}
	${CC} -L../../reg -lr_reg -L.. -lr_anal ${LDFLAGS} ${CFLAGS} -o anal_x86_simple.${EXT_SO} ${OBJ_X86_SIMPLE}
