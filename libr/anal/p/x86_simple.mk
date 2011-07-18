OBJ_X86_SIMPLE=anal_x86_simple.o
OBJ_X86_SIMPLE+=../arch/x86/dislen/dislen.o

STATIC_OBJ+=${OBJ_X86_SIMPLE}
TARGET_X86_SIMPLE=anal_x86_simple.${EXT_SO}

ALL_TARGETS+=${TARGET_X86_SIMPLE}
LIBS_X86_SIMPLE=r_anal r_reg r_lib r_syscall r_diff
MYLIBS=$(subst r_,-L../../,$(LIBS_X86_SIMPLE))

${TARGET_X86_SIMPLE}: ${OBJ_X86_SIMPLE}
	${CC} $(call libname,anal_x86_simple) ${MYLIBS} ${LDFLAGS} ${CFLAGS} -o anal_x86_simple.${EXT_SO} ${OBJ_X86_SIMPLE}
