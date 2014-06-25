N=anal_arm_gnu
OBJ_ARM=anal_arm_gnu.o ../../asm/arch/arm/winedbg/be_arm.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}
CFLAGS +=-I../asm/arch/include

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,$(N)) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_ARM) $(OBJ_ARM)
