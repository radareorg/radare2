OBJ_EDB=debug_edb.o

STATIC_OBJ+=${OBJ_EDB}
TARGET_EDB=debug_edb.${EXT_SO}

ALL_TARGETS+=${TARGET_EDB}

${TARGET_EDB}: ${OBJ_EDB}
	${CC} $(call libname,debug_edb) ${OBJ_EDB} ${CFLAGS} ${LDFLAGS} -o ${TARGET_EDB}
