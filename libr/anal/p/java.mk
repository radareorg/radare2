OBJ_JAVA=anal_java.o
OBJ_JAVA+=../asm/arch/java/javasm/java_ops.o

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=anal_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,anal_java) ${CFLAGS} -o anal_java.${EXT_SO} ${OBJ_JAVA}
