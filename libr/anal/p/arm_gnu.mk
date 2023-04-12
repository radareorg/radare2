N=anal_arm_gnu
OBJ_ARM_GNU=anal_arm_gnu.o
OBJ_ARM_GNU+=../../arch/p/arm/winedbg/be_arm.o

#arm32
OBJ_ARM_GNU+=../../arch/p/arm/gnu/arm-dis.o
OBJ_ARM_GNU+=../../arch/p/arm/gnu/floatformat.o
#arm64
OBJ_ARM_GNU+=../../arch/p/arm/aarch64/aarch64-dis.o
OBJ_ARM_GNU+=../../arch/p/arm/aarch64/aarch64-dis-2.o
OBJ_ARM_GNU+=../../arch/p/arm/aarch64/aarch64-opc.o
OBJ_ARM_GNU+=../../arch/p/arm/aarch64/aarch64-opc-2.o

STATIC_OBJ+=${OBJ_ARM_GNU}
TARGET_ARM=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}
CFLAGS +=-I../asm/arch/include

${TARGET_ARM}: ${OBJ_ARM_GNU}
	${CC} $(call libname,$(N)) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_ARM) $(OBJ_ARM_GNU)
