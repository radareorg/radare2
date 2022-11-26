OBJ_RISCV=p/riscv/plugin.o

STATIC_OBJ+=${OBJ_RISCV}
TARGET_RISCV=arch_riscv.${EXT_SO}

ALL_TARGETS+=${TARGET_RISCV}

${TARGET_RISCV}: ${OBJ_RISCV}
	${CC} $(call libname,arch_RISCV) ${LDFLAGS} ${CFLAGS} -o arch_riscv.${EXT_SO} ${OBJ_RISCV}
