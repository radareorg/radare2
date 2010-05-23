OBJ_DUMMY+=asm_dummy.o

TARGET_DUMMY=asm_dummy.${EXT_SO}
ALL_TARGETS+=${TARGET_DUMMY}
STATIC_OBJ+=${OBJ_DUMMY}

${TARGET_DUMMY}: ${OBJ_DUMMY}
	${CC} ${LDFLAGS} ${CFLAGS} -o asm_dummy.${EXT_SO} asm_dummy.o
