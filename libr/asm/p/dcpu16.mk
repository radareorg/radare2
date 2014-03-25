OBJ_DCPU16=asm_dcpu16.o
#OBJ_DCPU16+=../arch/dcpu16/asm.o
#OBJ_DCPU16+=../arch/dcpu16/dis.o

STATIC_OBJ+=${OBJ_DCPU16}
TARGET_DCPU16=asm_dcpu16.${EXT_SO}

ALL_TARGETS+=${TARGET_DCPU16}

${TARGET_DCPU16}: ${OBJ_DCPU16}
	${CC} $(call libname,asm_dcpu16) ${LDFLAGS} ${CFLAGS} -o asm_dcpu16.${EXT_SO} ${OBJ_DCPU16}
