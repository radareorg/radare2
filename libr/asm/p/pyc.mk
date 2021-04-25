PYC_ROOT=$(LIBR)/asm/arch/pyc
OBJ_PYC=asm_pyc.o
OBJ_PYC+=$(PYC_ROOT)/opcode_all.o
OBJ_PYC+=$(PYC_ROOT)/opcode_arg_fmt.o
OBJ_PYC+=$(PYC_ROOT)/opcode_anal.o
OBJ_PYC+=$(PYC_ROOT)/opcode.o
OBJ_PYC+=$(PYC_ROOT)/pyc_dis.o

STATIC_OBJ+=${OBJ_PYC}
TARGET_PYC=asm_pyc.$(EXT_SO)

ALL_TARGETS+=${TARGET_PYC}
CFLAGS+=-I$(PYC_ROOT)

${TARGET_PYC}: ${OBJ_PYC}
	${CC} ${CFLAGS} $(LDFLAGS) -o ${TARGET_PYC} ${OBJ_PYC} -lr_util

