OBJ_DALVIK=p/dalvik/plugin.o

STATIC_OBJ+=${OBJ_DALVIK}
TARGET_DALVIK=dalvik.${EXT_SO}

ALL_TARGETS+=${TARGET_DALVIK}

${TARGET_DALVIK}: ${OBJ_DALVIK}
	${CC} $(call libname,dalvik) ${LDFLAGS} ${CFLAGS} -o dalvik.${EXT_SO} ${OBJ_DALVIK}
