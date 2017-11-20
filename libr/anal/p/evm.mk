OBJ_evm=anal_evm.o
CFLAGS+=-I../asm/arch/evm/

STATIC_OBJ+=${OBJ_evm}
# OBJ_evm+=../../asm/arch/evm/evm_disas.o
TARGET_evm=anal_evm.${EXT_SO}

ALL_TARGETS+=${TARGET_evm}

${TARGET_evm}: ${OBJ_evm} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_evm) ${CFLAGS} \
		-o ${TARGET_evm} ${OBJ_evm}
