# capstone

OBJ_PPCCS=asm_ppc_cs.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_PPCCS}
SHARED_OBJ+=$(addprefix ../,${SHARED_PPCCS})
TARGET_PPCCS=asm_ppc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_PPCCS}

${TARGET_PPCCS}: ${OBJ_PPCCS}
	${CC} $(call libname,asm_ppc) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_PPCCS} ${OBJ_PPCCS} ${SHARED2_PPCCS}
