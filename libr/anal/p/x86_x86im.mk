OBJ_X86_X86IM=anal_x86_x86im.o
#OBJ_X86_X86IM+=../arch/x86/dislen/dislen.o

STATIC_OBJ+=${OBJ_X86}
TARGET_X86_X86IM=anal_x86_x86im.${EXT_SO}

ALL_TARGETS+=${TARGET_X86}

${TARGET_X86_X86IM}: ${OBJ_X86_X86IM}
	${CC} -shared ${CFLAGS} -o anal_x86_x86im.${EXT_SO} ${OBJ_X86_X86IM}
	@#strip -s anal_x86_x86im.${EXT_SO}
