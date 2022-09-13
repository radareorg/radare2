N=anal_arm_gnu
OBJ_ARM=anal_arm_gnu.o
OBJ_ARM+=../../asm/arch/arm/winedbg/be_arm.o

#arm32
OBJ_ARM+=../../asm/arch/arm/gnu/arm-dis.o
OBJ_ARM+=../../asm/arch/arm/gnu/floatformat.o
#arm64
OBJ_ARM+=../../asm/arch/arm/aarch64/aarch64-dis.o
OBJ_ARM+=../../asm/arch/arm/aarch64/aarch64-dis-2.o
OBJ_ARM+=../../asm/arch/arm/aarch64/aarch64-opc.o
OBJ_ARM+=../../asm/arch/arm/aarch64/aarch64-opc-2.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}
CFLAGS +=-I../asm/arch/include

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,$(N)) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_ARM) $(OBJ_ARM)
