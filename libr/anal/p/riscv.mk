OBJ_RISCV=anal_riscv.o

STATIC_OBJ+=${OBJ_RISCV}
TARGET_RISCV=anal_riscv.${EXT_SO}

ALL_TARGETS+=${TARGET_RISCV}

${TARGET_RISCV}: ${OBJ_RISCV}
	${CC} $(call libname,anal_RISCV) ${LDFLAGS} ${CFLAGS} -o anal_riscv.${EXT_SO} ${OBJ_RISCV}
