OBJ_BFLT=bin_bflt.o
OBJ_BFLT+=../format/bflt/bflt.o

STATIC_OBJ+=${OBJ_BFLT}
TARGET_BFLT=bin_bflt.${EXT_SO}

ALL_TARGETS+=${TARGET_BFLT}

${TARGET_BFLT}: ${OBJ_BFLT}
	${CC} $(call libname,bin_bflt) ${CFLAGS} \
		$(OBJ_BFLT) $(LINK) $(LDFLAGS)
