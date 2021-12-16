OBJ_EBC=anal_ebc.o
OBJ_EBC+=../arch/ebc/ebc_disas.o
STATIC_OBJ+=$(OBJ_EBC)
CFLAGS+=-Iarch/ebc/
TARGET_EBC=anal_ebc.$(EXT_SO)

ALL_TARGETS+=$(TARGET_EBC)

$(TARGET_EBC): $(OBJ_EBC) $(SHARED_OBJ)
	$(CC) $(call libname,anal_ebc) $(CFLAGS) -o $(TARGET_EBC) $(OBJ_EBC)
