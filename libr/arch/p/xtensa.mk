OBJ_XTENSA=p/xtensa/plugin.o
OBJ_XTENSA+=p/xtensa/gnu/xtensa-dis.o
OBJ_XTENSA+=p/xtensa/gnu/xtensa-isa.o
OBJ_XTENSA+=p/xtensa/gnu/xtensa-modules.o
OBJ_XTENSA+=p/xtensa/gnu/elf32-xtensa.o

STATIC_OBJ+=${OBJ_XTENSA}
TARGET_XTENSA=arch_xtensa.${EXT_SO}

ALL_TARGETS+=$(TARGET_XTENSA)
CFLAGS+=-I$(LTOP)/arch/include

$(TARGET_XTENSA): $(OBJ_XTENSA)
	$(CC) $(call libname,arch_xtensa) $(LDFLAGS) $(CFLAGS) -o arch_xtensa.$(EXT_SO) $(OBJ_XTENSA)
