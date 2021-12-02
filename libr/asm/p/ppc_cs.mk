# capstone

OBJ_PPCCS=asm_ppc_cs.o ../arch/ppc/libvle/vle.o ../arch/ppc/libps/libps.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=${OBJ_PPCCS}
SHARED_OBJ+=$(addprefix ../,${SHARED_PPCCS})
TARGET_PPCCS=asm_ppc_cs.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PPCCS}

${TARGET_PPCCS}: ${OBJ_PPCCS}
	${CC} -o ${TARGET_PPCCS} ${OBJ_PPCCS} \
		$(call libname,asm_ppc_cs) ${LDFLAGS} ${CFLAGS} \
		${SHARED2_PPCCS} ${CS_LDFLAGS}
endif
