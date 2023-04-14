N=arm_cs
OBJ_ARM_CS=p/arm_cs/plugin.o
OBJ_ARM_CS+=p/arm_cs/arm.o
OBJ_ARM_CS+=p/arm_cs/arm64.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_ARM_CS}

TARGET_ARM_CS=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_ARM_CS}

${TARGET_ARM_CS}: ${OBJ_ARM_CS}
	${CC} ${CFLAGS} $(call libname,$(N)) $(CS_CFLAGS) \
		-o $(TARGET_ARM_CS) ${OBJ_ARM_CS} $(CS_LDFLAGS)
