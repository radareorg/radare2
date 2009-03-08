OBJ_ARM=asm_arm.o
OBJ_ARM+=../arch/arm/gnu/arm-dis.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=asm_arm.so

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC} ${CFLAGS} -o asm_arm.so ${OBJ_ARM}
	@#strip -s asm_x86.so
