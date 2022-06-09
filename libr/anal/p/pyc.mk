PYC_ASM_ROOT=../../asm/arch/pyc/
OBJ_PYC=anal_pyc.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_all.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_anal.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode_arg_fmt.o
OBJ_PYC+=$(PYC_ASM_ROOT)/opcode.o
OBJ_PYC+=$(PYC_ASM_ROOT)/pyc_dis.o

STATIC_OBJ+=$(OBJ_PYC)
TARGET_PYC=anal_pyc.$(EXT_SO)

ALL_TARGETS+=$(TARGET_PYC)
PYC_ROOT=../asm/arch/pyc
CFLAGS+=-I$(PYC_ROOT)

$(TARGET_PYC): $(OBJ_PYC)
	$(CC) $(call libname,anal_pyc) $(CFLAGS) $(LDFLAGS) -o $(TARGET_PYC) $(OBJ_PYC) -lr_util
