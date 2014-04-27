OBJ_EBC=asm_ebc.o
OBJ_EBC+=../arch/ebc/ebc_disas.o

STATIC_OBJ+=${OBJ_EBC}
TARGET_EBC=asm_ebc.${EXT_SO}

ALL_TARGETS+=${TARGET_EBC}

${TARGET_EBC}: ${OBJ_EBC}
	${CC} ${LDFLAGS} ${CFLAGS} -I../arc/ebc/ -o ${TARGET_EBC} ${OBJ_EBC}
