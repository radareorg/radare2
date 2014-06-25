N=asm_arm_gnu
OBJ_ARM=$(N).o
OBJ_ARM+=../arch/arm/armass.o
#arm thumb + armv7
OBJ_ARM+=../arch/arm/gnu/arm-dis.o
#aarch64
OBJ_ARM+=../arch/arm/aarch64/aarch64-dis.o
OBJ_ARM+=../arch/arm/aarch64/aarch64-dis-2.o
OBJ_ARM+=../arch/arm/aarch64/aarch64-opc.o
OBJ_ARM+=../arch/arm/aarch64/aarch64-opc-2.o

STATIC_OBJ+=${OBJ_ARM}
TARGET_ARM=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_ARM}

${TARGET_ARM}: ${OBJ_ARM}
	${CC} $(call libname,$(N)) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_ARM) ${OBJ_ARM}
