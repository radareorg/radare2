# capstone

OBJ_ARMV35=asm_arm_v35.o
include ../arch/arm/v35arm64/deps.mk
OBJ_ARMV35+=$(addprefix ../arch/arm/v35arm64/disassembler/,$(ARM64V35_OBJS))

STATIC_OBJ+=${OBJ_ARMV35}
SHARED_OBJ+=${SHARED_ARMV35}
TARGET_ARMV35=asm_arm_v35.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ARMV35}

${TARGET_ARMV35}: ${OBJ_ARMV35}
	${CC} $(call libname,asm_arm_v35) ${LDFLAGS} ${CFLAGS} ${V35_CFLAGS} \
		-o ${TARGET_ARMV35} ${OBJ_ARMV35} ${V35_LDFLAGS}
endif
