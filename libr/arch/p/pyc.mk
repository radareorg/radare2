PYC_ROOT=p/pyc
OBJ_PYC=p/pyc/plugin.o
OBJ_PYC+=$(PYC_ROOT)/opcode_all.o
OBJ_PYC+=$(PYC_ROOT)/opcode_anal.o
OBJ_PYC+=$(PYC_ROOT)/opcode_arg_fmt.o
OBJ_PYC+=$(PYC_ROOT)/opcode.o
OBJ_PYC+=$(PYC_ROOT)/pyc_dis.o

STATIC_OBJ+=$(OBJ_PYC)
TARGET_PYC=arch_pyc.$(EXT_SO)

ALL_TARGETS+=$(TARGET_PYC)

$(TARGET_PYC): $(OBJ_PYC)
	$(CC) $(call libname,arch_pyc) $(CFLAGS) $(LDFLAGS) -o $(TARGET_PYC) $(OBJ_PYC) -lr_util
