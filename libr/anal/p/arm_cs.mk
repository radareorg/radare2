OBJ_ARM_CS=anal_arm_cs.o

include p/capstone.mk
STATIC_OBJ+=${OBJ_ARM_CS}

TARGET_ARM_CS=anal_arm_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM_CS}

${TARGET_ARM_CS}: ${OBJ_ARM_CS}
	${CC} ${CFLAGS} $(call libname,anal_arm_cs) $(CS_CFLAGS) \
		-o anal_arm_cs.${EXT_SO} ${OBJ_ARM_CS} $(CS_LDFLAGS)
