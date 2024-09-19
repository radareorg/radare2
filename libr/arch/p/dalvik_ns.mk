OBJ_DALVIK=p/dalvik_ns/plugin.o

STATIC_OBJ+=${OBJ_DALVIK}
TARGET_DALVIK=dalvik_ns.${EXT_SO}

ALL_TARGETS+=${TARGET_DALVIK}

${TARGET_DALVIK}: ${OBJ_DALVIK}
	${CC} $(call libname,dalvik_ns) ${LDFLAGS} ${CFLAGS} -o dalvik_ns.${EXT_SO} ${OBJ_DALVIK}
