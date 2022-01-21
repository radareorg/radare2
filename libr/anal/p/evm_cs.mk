OBJ_EVM_CS=anal_evm_cs.o

include $(CURDIR)capstone.mk

STATIC_OBJ+=$(OBJ_EVM_CS)
TARGET_EVM_CS=anal_evm_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_EVM_CS}

${TARGET_EVM_CS}: ${OBJ_EVM_CS}
	${CC} ${CFLAGS} $(call libname,anal_evm_cs) $(CS_CFLAGS) \
		-o anal_evm_cs.${EXT_SO} ${OBJ_EVM_CS} $(CS_LDFLAGS)
