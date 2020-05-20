OBJ_SYMBOLS=bin_symbols.o
OBJ_SYMBOLS+=../format/mach0/coresymbolication.o

STATIC_OBJ+=${OBJ_SYMBOLS}
TARGET_SYMBOLS=bin_symbols.${EXT_SO}

ALL_TARGETS+=${TARGET_SYMBOLS}

${TARGET_SYMBOLS}: ${OBJ_SYMBOLS}
	-${CC} $(call libname,bin_mach0) ${CFLAGS} \
		${OBJ_SYMBOLS} ${SHLR}/sdb/src/libsdb.a \
		$(LINK) $(LDFLAGS) 
