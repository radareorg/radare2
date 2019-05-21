OBJ_RISCV_CS=anal_riscv_cs.o

include $(CURDIR)capstone.mk

STATIC_OBJ+=$(OBJ_RISCV_CS)
TARGET_RISCV_CS=anal_riscv_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_RISCV_CS}

${TARGET_RISCV_CS}: ${OBJ_RISCV_CS}
	${CC} ${CFLAGS} $(call libname,anal_riscv_cs) $(CS_CFLAGS) \
		-o anal_riscv_cs.${EXT_SO} ${OBJ_RISCV_CS} $(CS_LDFLAGS)
