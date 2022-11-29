OBJ_ARMARCH=p/arm/plugin.o
OBJ_ARMARCH+=p/arm/armass64.o
OBJ_ARMARCH+=p/arm/armass.o

STATIC_OBJ+=${OBJ_ARMARCH}
TARGET_ARMARCH=arch_arm.${EXT_SO}

ALL_TARGETS+=${TARGET_ARMARCH}

${TARGET_ARMARCH}: ${OBJ_ARMARCH}
	${CC} ${CFLAGS} $(call libname,arch_arm) $(CS_CFLAGS) \
		-o arch_arm.${EXT_SO} ${OBJ_ARMARCH} $(CS_LDFLAGS)
