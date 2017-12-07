OBJ_CHIP8=asm_chip8.o

STATIC_OBJ+=${OBJ_CHIP8}
TARGET_CHIP8=asm_chip8.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_CHIP8}

${TARGET_CHIP8}: ${OBJ_CHIP8}
	${CC} ${call libname,asm_chip8} ${CFLAGS} -o ${TARGET_CHIP8} ${OBJ_CHIP8}
endif
