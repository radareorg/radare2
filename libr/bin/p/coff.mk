OBJ_COFF=bin_coff.o
OBJ_COFF+=../format/coff/coff.o

STATIC_OBJ+=${OBJ_COFF}
TARGET_COFF=bin_coff.${EXT_SO}

ALL_TARGETS+=${TARGET_COFF}

${TARGET_COFF}: ${OBJ_COFF}
	${CC} $(call libname,bin_coff) ${CFLAGS} \
		$(OBJ_COFF) $(LINK) $(LDFLAGS)
