OBJ_DUMMY+=parse_dummy.o

TARGET_DUMMY=parse_dummy.${EXT_SO}
ALL_TARGETS+=${TARGET_DUMMY}
STATIC_OBJ+=${OBJ_DUMMY}

${TARGET_DUMMY}: ${OBJ_DUMMY}
	${CC} -shared ${CFLAGS} -o ${TARGET_DUMMY} ${OBJ_DUMMY}
	@#strip -s asm_dummy.${EXT_SO}
