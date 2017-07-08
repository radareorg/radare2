OBJ_EVM=asm_evm.o

TARGET_EVM=asm_evm.${EXT_SO}
STATIC_OBJ+=${OBJ_EVM}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_EVM}
${TARGET_EVM}: ${OBJ_EVM}
	${CC} $(call libname,asm_evm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_EVM} ${OBJ_EVM}
endif
