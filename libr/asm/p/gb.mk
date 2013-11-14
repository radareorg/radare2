OBJ_GB=asm_gb.o

STATIC_OBJ+=${OBJ_GB}
TARGET_GB=asm_gb.${EXT_SO}

ALL_TARGETS+=${TARGET_GB}

${TARGET_GB}: ${OBJ_GB}
	${CC} ${call libname,asm_gb} ${CFLAGS} -o ${TARGET_GB} ${OBJ_GB}
