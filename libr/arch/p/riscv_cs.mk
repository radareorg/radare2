OBJ_RISCV_CS=p/riscv_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=$(OBJ_RISCV_CS)
TARGET_RISCV_CS=arch_riscv_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_RISCV_CS}

${TARGET_RISCV_CS}: ${OBJ_RISCV_CS}
	${CC} ${CFLAGS} $(call libname,arch_riscv_cs) $(CS_CFLAGS) \
		-o arch_riscv_cs.${EXT_SO} ${OBJ_RISCV_CS} $(CS_LDFLAGS)
