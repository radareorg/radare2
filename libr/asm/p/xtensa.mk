OBJ_XTENSA=asm_xtensa.o
OBJ_XTENSA+=../arch/xtensa/gnu/xtensa-dis.o
OBJ_XTENSA+=../arch/xtensa/gnu/xtensa-isa.o
OBJ_XTENSA+=../arch/xtensa/gnu/xtensa-modules.o
OBJ_XTENSA+=../arch/xtensa/gnu/elf32-xtensa.o

STATIC_OBJ+=${OBJ_XTENSA}
TARGET_XTENSA=asm_xtensa.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_XTENSA}

${TARGET_XTENSA}: ${OBJ_XTENSA}
	${CC} $(call libname,asm_xtensa) ${LDFLAGS} ${CFLAGS} -o asm_xtensa.${EXT_SO} ${OBJ_XTENSA}
endif
