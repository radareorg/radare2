OBJ_CHIP8=p/chip8/plugin.o

STATIC_OBJ+=${OBJ_CHIP8}
TARGET_CHIP8=arch_chip8.${EXT_SO}

ALL_TARGETS+=${TARGET_CHIP8}

${TARGET_CHIP8}: ${OBJ_CHIP8}
	${CC} $(call libname,arch_chip8) ${CFLAGS} -o arch_chip8.${EXT_SO} ${OBJ_CHIP8}
