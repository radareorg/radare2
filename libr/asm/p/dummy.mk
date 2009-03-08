OBJ_DUMMY+=asm_dummy.o

TARGET_DUMMY=asm_dummy.so
ALL_TARGETS+=${TARGET_DUMMY}
STATIC_OBJ+=${OBJ_DUMMY}

${TARGET_DUMMY}: ${OBJ_DUMMY}
	${CC} ${CFLAGS} -o asm_dummy.so asm_dummy.o
	@#strip -s asm_dummy.so
