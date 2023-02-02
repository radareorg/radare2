OBJ_OR1K=p/or1k/plugin.o
OBJ_OR1K+=p/or1k/or1k_disas.o

STATIC_OBJ+=$(OBJ_OR1K)
TARGET_OR1K=p/arch_or1k.$(EXT_SO)

ALL_TARGETS+=$(TARGET_OR1K)

${TARGET_OR1K}: $(OBJ_OR1K)
	${CC} $(call libname,arch_or1k) $(LDFLAGS) $(CFLAGS) -o arch_or1k.$(EXT_SO) $(OBJ_OR1K)
