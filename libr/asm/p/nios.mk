OBJ_NIOS=asm_nios.o
OBJ_NIOS+=../arch/nios/gnu/nios2-dis.o
OBJ_NIOS+=../arch/nios/gnu/nios2-opc.o

STATIC_OBJ+=${OBJ_NIOS}
TARGET_NIOS=asm_nios.${EXT_SO}

ALL_TARGETS+=${TARGET_NIOS}

${TARGET_NIOS}: ${OBJ_NIOS}
	${CC} $(call libname,asm_nios) ${LDFLAGS} ${CFLAGS} -o asm_nios.${EXT_SO} ${OBJ_NIOS}
