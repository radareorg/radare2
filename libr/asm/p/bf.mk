OBJ_BF=asm_bf.o

TARGET_BF=asm_bf.${EXT_SO}
ALL_TARGETS+=${TARGET_BF}
STATIC_OBJ+=${OBJ_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC} $(call libname,asm_bf) ${LDFLAGS} ${CFLAGS} -o ${TARGET_BF} ${OBJ_BF}
