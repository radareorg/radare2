OBJ_LANAI=p/lanai/plugin.o
OBJ_LANAI+=p/lanai/gnu/lanai-dis.o
OBJ_LANAI+=p/lanai/gnu/lanai-opc.o

STATIC_OBJ+=$(OBJ_LANAI)
TARGET_LANAI=p/arch_lanai.$(EXT_SO)

ALL_TARGETS+=$(TARGET_LANAI)

${TARGET_LANAI}: $(OBJ_LANAI)
	${CC} $(call libname,arch_lanai) $(LDFLAGS) $(CFLAGS) -o arch_lanai.$(EXT_SO) $(OBJ_LANAI)
