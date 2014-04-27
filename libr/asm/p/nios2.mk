OBJ_NIOS2=asm_nios2.o
OBJ_NIOS2+=../arch/nios/gnu/nios2-dis.o
OBJ_NIOS2+=../arch/nios/gnu/nios2-opc.o

STATIC_OBJ+=${OBJ_NIOS2}
TARGET_NIOS2=asm_nios2.${EXT_SO}

ALL_TARGETS+=${TARGET_NIOS2}

${TARGET_NIOS2}: ${OBJ_NIOS2}
	${CC} $(call libname,asm_nios2) ${LDFLAGS} ${CFLAGS} \
		-o asm_nios2.${EXT_SO} ${OBJ_NIOS2}
