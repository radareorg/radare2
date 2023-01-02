OBJ_X86_NASM=p/x86_nasm/plugin.o

STATIC_OBJ+=${OBJ_X86_NASM}
TARGET_X86_NASM=arch_x86_nasm.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_X86_NASM}

${TARGET_X86_NASM}: ${OBJ_X86_NASM}
	${CC} $(call libname,arch_x86_nasm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86_NASM} ${OBJ_X86_NASM}
endif
