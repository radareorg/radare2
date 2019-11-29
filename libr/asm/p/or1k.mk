OBJ_OR1K=asm_or1k.o
OBJ_OR1K+=../arch/or1k/or1k_disas.o
CFLAGS+=-I./arch/or1k/

STATIC_OBJ+=${OBJ_OR1K}
TARGET_OR1K=asm_or1k.${EXT_SO}

ALL_TARGETS+=${TARGET_OR1K}

${TARGET_OR1K}: ${OBJ_OR1K}
	${CC} $(call libname,asm_or1k) ${LDFLAGS} ${CFLAGS} -o asm_or1k.${EXT_SO} ${OBJ_OR1K}
