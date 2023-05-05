OBJ_SM5XX=p/sm5xx/plugin.o
OBJ_SM5XX+=p/sm5xx/sm5xx.o

STATIC_OBJ+=$(OBJ_SM5XX)
TARGET_SM5XX=p/arch_sm5xx.$(EXT_SO)

ALL_TARGETS+=$(TARGET_SM5XX)

${TARGET_SM5XX}: $(OBJ_SM5XX)
	${CC} $(call libname,arch_sm5xx) $(LDFLAGS) $(CFLAGS) -o arch_sm5xx.$(EXT_SO) $(OBJ_SM5XX)
