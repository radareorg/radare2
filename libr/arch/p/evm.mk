OBJ_EVM=p/evm/plugin.o

include $(CURDIR)/p/capstone.mk

STATIC_OBJ+=$(OBJ_EVM)
TARGET_EVM=arch_evm.${EXT_SO}

ALL_TARGETS+=${TARGET_EVM}

${TARGET_EVM}: ${OBJ_EVM}
	${CC} ${CFLAGS} $(call libname,arch_evm) $(CS_CFLAGS) \
		-o arch_evm.${EXT_SO} ${OBJ_EVM} $(CS_LDFLAGS)
