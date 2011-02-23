OBJ_MSIL=asm_msil.o
#OBJ_MSIL+=../arch/msil/demsil.o

STATIC_OBJ+=${OBJ_MSIL}
TARGET_MSIL=asm_msil.${EXT_SO}

ALL_TARGETS+=${TARGET_MSIL}

${TARGET_MSIL}: ${OBJ_MSIL}
	${CC} ${LDFLAGS} ${CFLAGS} -o asm_msil.${EXT_SO} ${OBJ_MSIL}
