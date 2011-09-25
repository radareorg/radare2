OBJ_ARM=bp_arm.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=bp_arm.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC_LIB} $(call libname,bp_arm) ${CFLAGS} -o ${TARGET_ARM} ${OBJ_ARM}
