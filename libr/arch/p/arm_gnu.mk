N=arch_arm_gnu
OBJ_ARM_GNU=p/arm/plugin_gnu.o
OBJ_ARM_GNU+=p/arm/gnu/arm-dis.o
# OBJ_ARM_GNU+=p/arm/gnu/floatformat.o

OBJ_ARM_GNU+=p/arm/winedbg/be_arm.o
#arm64
OBJ_ARM_GNU+=p/arm/aarch64/aarch64-dis.o
OBJ_ARM_GNU+=p/arm/aarch64/aarch64-dis-2.o
OBJ_ARM_GNU+=p/arm/aarch64/aarch64-opc.o
OBJ_ARM_GNU+=p/arm/aarch64/aarch64-opc-2.o

STATIC_OBJ+=${OBJ_ARM_GNU}
TARGET_ARM=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM_GNU}
	${CC} $(call libname,$(N)) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_ARM) $(OBJ_ARM_GNU)
