OBJ_CRIS=anal_cris.o
OBJ_CRIS+=../../asm/arch/cris/gnu/cris-dis.o
OBJ_CRIS+=../../asm/arch/cris/gnu/cris-opc.o

STATIC_OBJ+=$(OBJ_CRIS)
TARGET_CRIS=anal_cris.$(EXT_SO)

ALL_TARGETS+=$(TARGET_CRIS)

$(TARGET_CRIS): $(OBJ_CRIS)
	$(CC) $(CFLAGS) $(call libname,anal_cris) -o anal_cris.$(EXT_SO) $(OBJ_CRIS)
