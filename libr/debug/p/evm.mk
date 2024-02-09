#LDFLAGS+=-lcurl

#-include ../../global.mk
#-include ../../../global.mk

OBJ_EVM=debug_evm.o

STATIC_OBJ+=${OBJ_EVM}
TARGET_EVM=debug_evm.${LIBEXT}
ALL_TARGETS+=${TARGET_EVM}

${TARGET_EVM}: ${OBJ_EVM}
	${CC} $(call libname,debug_evm) ${CFLAGS} -o ${TARGET_EVM} \
		${LDFLAGS} ${OBJ_EVM} ${LINKFLAGS}
