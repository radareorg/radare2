OBJ_UXN=p/uxn/plugin.o
# OBJ_UXN+=p/uxn/uxndisass.o

STATIC_OBJ+=$(OBJ_UXN)
TARGET_UXN=p/arch_uxn.$(EXT_SO)

ALL_TARGETS+=$(TARGET_UXN)

${TARGET_UXN}: $(OBJ_UXN)
	${CC} $(call libname,arch_uxn) $(LDFLAGS) $(CFLAGS) -o arch_uxn.$(EXT_SO) $(OBJ_UXN)
