OBJ_X86_X86IM=anal_x86_x86im.o
OBJ_X86_X86IM+=../arch/x86/x86im/x86im.o ../arch/x86/x86im/x86im_fmt.o

STATIC_OBJ+=${OBJ_X86_X86IM}
TARGET_X86_X86IM=anal_x86_x86im.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_X86IM}
CFLAGS+=-D__X86IM_USE_FMT__

${TARGET_X86_X86IM}: ${OBJ_X86_X86IM}
	${CC} -shared ${CFLAGS} -o anal_x86_x86im.${EXT_SO} ${OBJ_X86_X86IM}
	@#strip -s anal_x86_x86im.${EXT_SO}
