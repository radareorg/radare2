OBJ_CRIS=p/cris/plugin.o
OBJ_CRIS+=p/cris/gnu/cris-dis.o
OBJ_CRIS+=p/cris/gnu/cris-opc.o

STATIC_OBJ+=$(OBJ_CRIS)
TARGET_CRIS=cris.$(EXT_SO)

ALL_TARGETS+=$(TARGET_CRIS)

$(TARGET_CRIS): $(OBJ_CRIS)
	$(CC) $(CFLAGS) $(call libname,cris) -o cris.$(EXT_SO) $(OBJ_CRIS)
