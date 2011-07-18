OBJ_JAVA=asm_java.o
OBJ_JAVA+=../arch/java/javasm/javasm.o
OBJ_JAVA+=../arch/java/javasm/java_ops.o

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=asm_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,asm_java) ${LDFLAGS} ${CFLAGS} -o asm_java.${EXT_SO} ${OBJ_JAVA}
