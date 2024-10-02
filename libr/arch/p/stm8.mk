OBJ_STM8=p/stm8/plugin.o
OBJ_STM8+=p/stm8/pseudo.o

STATIC_OBJ+=$(OBJ_STM8)
TARGET_STM8=arch_stm8.$(EXT_SO)

ALL_TARGETS+=$(TARGET_STM8)

$(TARGET_STM8): $(OBJ_STM8)
	$(CC) $(call libname,arch_stm8) $(LDFLAGS) $(CFLAGS) -o arch_stm8.$(EXT_SO) $(OBJ_STM8)
