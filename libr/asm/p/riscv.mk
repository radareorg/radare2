OBJ_RISCV=asm_riscv.o
#implicitly included
#OBJ_RISCV+=../arch/riscv/riscv.o
#OBJ_RISCV+=../arch/riscv/riscv-opc.o

STATIC_OBJ+=${OBJ_RISCV}
TARGET_RISCV=asm_riscv.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_RISCV}

${TARGET_RISCV}: ${OBJ_RISCV}
	${CC} ${call libname,asm_RISCV} ${CFLAGS} -o ${TARGET_RISCV} ${OBJ_RISCV}
endif
