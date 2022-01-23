# capstone

OBJ_EVMCS=asm_evm_cs.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=${OBJ_EVMCS}
TARGET_EVMCS=asm_evm_cs.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_EVMCS}
${TARGET_EVMCS}: ${OBJ_EVMCS}
	${CC} $(call libname,asm_evm_cs) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_EVMCS} ${OBJ_EVMCS} ${CS_LDFLAGS}
endif
