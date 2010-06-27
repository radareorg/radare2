OBJ_X86=anal_x86.o
OBJ_X86+=../arch/x86/dislen/dislen.o

STATIC_OBJ+=${OBJ_X86}
TARGET_X86=anal_x86.${EXT_SO}

ALL_TARGETS+=${TARGET_X86}

${TARGET_X86}: ${OBJ_X86}
	${CC} -L../../reg -lr_reg -L.. -lr_anal ${LDFLAGS} ${CFLAGS} -o anal_x86.${EXT_SO} ${OBJ_X86}
