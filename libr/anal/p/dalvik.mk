OBJ_DALVIK=anal_dalvik.o

STATIC_OBJ+=${OBJ_DALVIK}
TARGET_DALVIK=anal_dalvik.${EXT_SO}

ALL_TARGETS+=${TARGET_DALVIK}

${TARGET_DALVIK}: ${OBJ_DALVIK}
	${CC} $(call libname,anal_dalvik) ${LDFLAGS} ${CFLAGS} -o anal_dalvik.${EXT_SO} ${OBJ_DALVIK}
