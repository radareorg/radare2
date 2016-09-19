OBJ_XTENSA=anal_xtensa.o

STATIC_OBJ+=${OBJ_XTENSA}
TARGET_XTENSA=anal_xtensa.${EXT_SO}

ALL_TARGETS+=$(TARGET_XTENSA)

$(TARGET_XTENSA): $(OBJ_XTENSA)
	$(CC) $(call libname,anal_xtensa) -I$(LTOP)/asm/arch/include/ \
		$(LDFLAGS) $(CFLAGS) -o anal_xtensa.$(EXT_SO) $(OBJ_XTENSA)
