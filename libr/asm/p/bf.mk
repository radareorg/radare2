OBJ_BF=asm_bf.o

TARGET_BF=asm_bf.so
ALL_TARGETS+=${TARGET_BF}
STATIC_OBJ+=${OBJ_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC} ${CFLAGS} -o ${TARGET_BF} ${OBJ_BF}
	@#strip -s asm_x86.so
