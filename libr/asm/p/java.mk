OBJ_JAVA=asm_java.o
OBJ_JAVA+=../arch/java/javasm/javasm.o

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=asm_java.so

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} ${CFLAGS} -o asm_java.so ${OBJ_JAVA}
	@#strip -s asm_x86.so
