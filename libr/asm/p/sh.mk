OBJ_SH=asm_sh.o
OBJ_SH+=../arch/sh/gnu/sh-dis.o

STATIC_OBJ+=${OBJ_SH}

TARGET_SH=asm_sh.${EXT_SO}
ALL_TARGETS+=${TARGET_SH}

${TARGET_SH}: ${OBJ_SH}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_SH} ${OBJ_SH}
