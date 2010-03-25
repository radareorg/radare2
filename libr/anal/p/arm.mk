OBJ_ARM=anal_arm.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=anal_arm.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC} -shared ${CFLAGS} -o anal_arm.${EXT_SO} ${OBJ_ARM}
	@#strip -s anal_x86.${EXT_SO}
