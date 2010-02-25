OBJ_DUMMY+=cmd_dummy.o

TARGET_DUMMY=cmd_dummy.${EXT_SO}
ALL_TARGETS+=${TARGET_DUMMY}
STATIC_OBJ+=${OBJ_DUMMY}

${TARGET_DUMMY}: ${OBJ_DUMMY}
	${CC} ${CFLAGS} -o cmd_dummy.${EXT_SO} cmd_dummy.o
