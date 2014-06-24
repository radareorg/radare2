# capstone

OBJ_ARMCS=asm_arm_cs.o

include p/capstone.mk

#SHARED2_ARMCS=$(addprefix ../,${SHARED_ARMCS})

STATIC_OBJ+=${OBJ_ARMCS}
SHARED_OBJ+=${SHARED_ARMCS}
TARGET_ARMCS=asm_arm_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_ARMCS}

${TARGET_ARMCS}: ${OBJ_ARMCS}
	${CC} $(call libname,asm_arm) ${LDFLAGS} ${CFLAGS} ${CS_CFLAGS} \
		-o ${TARGET_ARMCS} ${OBJ_ARMCS} ${CS_LDFLAGS}
