# capstone

OBJ_ARMV35=asm_arm_v35.o
OBJ_ARMV35+=../arch/arm/v35arm64/arm64dis.o

STATIC_OBJ+=${OBJ_ARMV35}
SHARED_OBJ+=${SHARED_ARMV35}
TARGET_ARMV35=asm_arm_v35.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ARMV35}

${TARGET_ARMV35}: ${OBJ_ARMV35}
	${CC} $(call libname,asm_arm) ${LDFLAGS} ${CFLAGS} ${V35_CFLAGS} \
		-o ${TARGET_ARMV35} ${OBJ_ARMV35} ${V35_LDFLAGS}
endif
