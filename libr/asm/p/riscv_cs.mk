# capstone

OBJ_RISCVCS=asm_riscv_cs.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=${OBJ_RISCVCS}
TARGET_RISCVCS=asm_riscv_cs.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_RISCVCS}
${TARGET_RISCVCS}: ${OBJ_RISCVCS}
	${CC} $(call libname,asm_riscv_cs) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_RISCVCS} ${OBJ_RISCVCS} ${CS_LDFLAGS}
endif
