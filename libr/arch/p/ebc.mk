OBJ_EBC=p/ebc/plugin.o
OBJ_EBC+=p/ebc/ebc_disas.o
STATIC_OBJ+=$(OBJ_EBC)
CFLAGS+=-Iarch/ebc/
TARGET_EBC=ebc.$(EXT_SO)

ALL_TARGETS+=$(TARGET_EBC)

$(TARGET_EBC): $(OBJ_EBC) $(SHARED_OBJ)
	$(CC) $(call libname,ebc) $(CFLAGS) -o $(TARGET_EBC) $(OBJ_EBC)
