OBJ_ARM=anal_arm.o ../../asm/arch/arm/winedbg/be_arm.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=anal_arm.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}
CFLAGS +=-I../asm/arch/include

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,anal_arm) ${LDFLAGS} ${CFLAGS} -o anal_arm.${EXT_SO} ${OBJ_ARM}
