OBJ_ARM_CS=anal_arm_cs.o
SHARED_ARM_CS=../../shlr/capstone/libcapstone.a
STATIC_OBJ+=$(OBJ_ARM_CS)

SHARED_OBJ+=${SHARED_ARM_CS}
TARGET_ARM_CS=anal_arm_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_ARM_CS}

${TARGET_ARM_CS}: ${OBJ_ARM_CS}
	${CC} ${CFLAGS} $(call libname,anal_arm_cs) \
		-o anal_arm_cs.${EXT_SO} ${OBJ_ARM_CS}
