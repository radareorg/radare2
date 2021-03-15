PYC_ASM_ROOT=../../asm/arch/pyc/
OBJ_PYC=anal_pyc.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_10.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_11.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_12.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_13.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_14.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_15.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_16.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_20.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_21.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_22.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_23.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_24.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_25.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_26.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_27.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_2x.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_30.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_31.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_32.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_33.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_34.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_35.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_36.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_37.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_38.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_39.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_3x.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_anal.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_arg_fmt.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode.o

STATIC_OBJ+=${OBJ_PYC}
TARGET_PYC=anal_pyc.$(EXT_SO)

ALL_TARGETS+=${TARGET_PYC}
PYC_ROOT=../asm/arch/pyc
CFLAGS+=-I$(PYC_ROOT)

${TARGET_PYC}: ${OBJ_PYC}
	${CC} $(call libname,anal_pyc) ${CFLAGS} $(LDFLAGS) -o ${TARGET_PYC} ${OBJ_PYC} -lr_util
