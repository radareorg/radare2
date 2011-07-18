OBJ_ARM=anal_arm.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=anal_arm.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,anal_asm) ${LDFLAGS} ${CFLAGS} -o anal_arm.${EXT_SO} ${OBJ_ARM}
