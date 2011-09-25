OBJ_JAVA=bin_java.o ../format/java/java.o

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=bin_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC_LIB} ${TARGET_JAVA} $(call libname,bin_java) ${CFLAGS} ${OBJ_JAVA}
