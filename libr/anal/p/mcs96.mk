OBJ_MCS96=anal_mcs96.o

STATIC_OBJ+=$(OBJ_MCS96)
TARGET_MCS96=anal_mcs96.$(EXT_SO)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=$(TARGET_MCS96)

$(TARGET_MCS96): $(OBJ_MCS96)
	$(CC) $(call libname,anal_mcs96) $(CFLAGS) -o $(TARGET_MCS96) $(OBJ_MCS96)
endif
