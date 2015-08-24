OBJ_ARM_AS=asm_arm_as.o

STATIC_OBJ+=${OBJ_ARM_AS}
TARGET_ARM_AS=asm_arm_as.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ARM_AS}

${TARGET_ARM_AS}: ${OBJ_ARM_AS}
	${CC} $(call libname,asm_arm_nasm) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_ARM_AS} ${OBJ_ARM_AS}
endif
