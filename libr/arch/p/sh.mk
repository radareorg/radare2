OBJ_SH=p/sh/plugin.o
OBJ_SH+=p/sh/gnu/sh-dis.o

STATIC_OBJ+=$(OBJ_SH)
TARGET_SH=arch_sh.$(EXT_SO)

ALL_TARGETS+=$(TARGET_SH)

$(TARGET_SH): $(OBJ_SH)
	$(CC) $(call libname,arch_sh) $(LDFLAGS) $(CFLAGS) -o arch_sh.$(EXT_SO) $(OBJ_SH)
