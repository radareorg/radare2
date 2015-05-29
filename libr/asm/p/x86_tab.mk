OBJ_X86_TAB=asm_x86_tab.o

STATIC_OBJ+=${OBJ_X86_TAB}
TARGET_X86_TAB=asm_x86_tab.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_X86_TAB}

${TARGET_X86_TAB}: ${OBJ_X86_TAB}
	${CC} $(call libname,asm_x86_tab) ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86_TAB} ${OBJ_X86_TAB}
endif
