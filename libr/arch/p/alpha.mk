OBJ_ALPHA=p/alpha/plugin.o
OBJ_ALPHA+=p/alpha/alpha-dis.o
OBJ_ALPHA+=p/alpha/alpha-opc.o

STATIC_OBJ+=$(OBJ_ALPHA)
TARGET_ALPHA=arch_alpha.$(EXT_SO)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=$(TARGET_ALPHA)

$(TARGET_ALPHA): $(OBJ_ALPHA)
	$(CC) $(call libname,arch_alpha) $(LDFLAGS) \
		$(CFLAGS) -o arch_alpha.$(EXT_SO) $(OBJ_ALPHA)
endif
