OBJ_S1C88=p/s1c88/plugin.o

STATIC_OBJ+=$(OBJ_S1C88)
TARGET_S1C88=p/arch_s1c88.$(EXT_SO)

ALL_TARGETS+=$(TARGET_S1C88)

${TARGET_S1C88}: $(OBJ_S1C88)
	${CC} $(call libname,arch_s1c88) $(LDFLAGS) $(CFLAGS) -o arch_s1c88.$(EXT_SO) $(OBJ_S1C88)
