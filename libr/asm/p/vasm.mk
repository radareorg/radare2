OBJ_VASM=asm_vasm.o

STATIC_OBJ+=${OBJ_VASM}
TARGET_VASM=asm_vasm.${EXT_SO}

ALL_TARGETS+=${TARGET_VASM}

${TARGET_VASM}: ${OBJ_VASM}
	${CC} $(call libname,asm_vasm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_VASM} ${OBJ_VASM}
