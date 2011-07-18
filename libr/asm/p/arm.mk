OBJ_ARM=asm_arm.o
OBJ_ARM+=../arch/arm/gnu/arm-dis.o
OBJ_ARM+=../arch/arm/armass.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=asm_arm.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,asm_arm) ${LDFLAGS} ${CFLAGS} -o asm_arm.${EXT_SO} ${OBJ_ARM}
