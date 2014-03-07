# capstone

OBJ_ARMCS=asm_arm_cs.o
CFLAGS+=-I../../shlr/capstone/include
SHARED_ARMCS=../../shlr/capstone/libcapstone.a

SHARED2_ARMCS=$(addprefix ../,${SHARED_ARMCS})

STATIC_OBJ+=${OBJ_ARMCS}
SHARED_OBJ+=${SHARED_ARMCS}
TARGET_ARMCS=asm_arm_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_ARMCS}

${TARGET_ARMCS}: ${OBJ_ARMCS}
	${CC} $(call libname,asm_arm) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_ARMCS} ${OBJ_ARMCS} ${SHARED2_ARMCS}
