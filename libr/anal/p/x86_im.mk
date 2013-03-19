OBJ_X86=anal_x86_im.o
OBJ_X86+=../arch/x86/x86im/x86im.o ../arch/x86/x86im/x86im_fmt.o

STATIC_OBJ+=${OBJ_X86}
TARGET_X86=anal_x86.${EXT_SO}

ALL_TARGETS+=${TARGET_X86}
CFLAGS+=-D__X86IM_USE_FMT__

${TARGET_X86}: ${OBJ_X86}
	${CC} $(call libname,anal_x86) ${CFLAGS} -o anal_x86_im.${EXT_SO} ${OBJ_X86}
