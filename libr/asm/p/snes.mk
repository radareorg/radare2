OBJ_SNES=asm_snes.o

STATIC_OBJ+=${OBJ_SNES}
TARGET_SNES=asm_snes.${EXT_SO}

ALL_TARGETS+=${TARGET_SNES}

${TARGET_SNES}: ${OBJ_SNES}
	${CC} ${call libname,asm_snes} ${CFLAGS} -o ${TARGET_SNES} ${OBJ_SNES}
