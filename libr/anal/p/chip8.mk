OBJ_CHIP8=anal_chip8.o

STATIC_OBJ+=${OBJ_CHIP8}
TARGET_CHIP8=anal_chip8.${EXT_SO}

ALL_TARGETS+=${TARGET_CHIP8}

${TARGET_CHIP8}: ${OBJ_CHIP8}
	${CC} $(call libname,anal_chip8) ${CFLAGS} -o anal_chip8.${EXT_SO} ${OBJ_CHIP8}
