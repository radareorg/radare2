OBJ_DUMMY+=cmd_dummy.o

STATIC_OBJ+=${OBJ_DUMMY}
TARGET_DUMMY=cmd_dummy.${EXT_SO}

ALL_TARGETS+=${TARGET_DUMMY}

${TARGET_DUMMY}: ${OBJ_DUMMY}
	${CC} $(call libname,cmd_dummy) ${CFLAGS} -o ${TARGET_DUMMY} ${OBJ_DUMMY}
