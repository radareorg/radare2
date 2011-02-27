OBJ_X86=asm_x86.o
# udis86
OBJ_X86+=../arch/x86/udis86/syn.o
OBJ_X86+=../arch/x86/udis86/input.o
OBJ_X86+=../arch/x86/udis86/udis86.o
OBJ_X86+=../arch/x86/udis86/decode.o
OBJ_X86+=../arch/x86/udis86/itab.o
OBJ_X86+=../arch/x86/udis86/syn-intel.o
OBJ_X86+=../arch/x86/udis86/syn-att.o

STATIC_OBJ+=${OBJ_X86}
TARGET_X86=asm_x86.${EXT_SO}

ALL_TARGETS+=${TARGET_X86}

${TARGET_X86}: ${OBJ_X86}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_X86} ${OBJ_X86}
