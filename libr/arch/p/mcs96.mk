OBJ_MCS96=p/mcs96/plugin.o

STATIC_OBJ+=$(OBJ_MCS96)
TARGET_MCS96=arch_mcs96.$(EXT_SO)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=$(TARGET_MCS96)

$(TARGET_MCS96): $(OBJ_MCS96)
	$(CC) $(call libname,arch_mcs96) $(CFLAGS) -o $(TARGET_MCS96) $(OBJ_MCS96)
endif
