OBJ_EBC=asm_ebc.o
OBJ_EBC+=../arch/ebc/ebc_disas.o
CFLAGS+=-I./arch/ebc/

STATIC_OBJ+=${OBJ_EBC}
TARGET_EBC=asm_ebc.${EXT_SO}

ALL_TARGETS+=${TARGET_EBC}

${TARGET_EBC}: ${OBJ_EBC}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_EBC} ${OBJ_EBC}
