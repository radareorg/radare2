OBJ_COFF_BIGOBJ=bin_coff_bigobj.o
OBJ_COFF_BIGOBJ+=../format/coff/coff_bigobj.o

STATIC_OBJ+=${OBJ_COFF_BIGOBJ}
TARGET_COFF_BIGOBJ=bin_coff_bigobj.${EXT_SO}

ALL_TARGETS+=${TARGET_COFF_BIGOBJ}

${TARGET_COFF_BIGOBJ}: ${OBJ_COFF_BIGOBJ}
	${CC} $(call libname,bin_coff_bigobj) ${CFLAGS} \
		$(OBJ_COFF_BIGOBJ) $(LINK) $(LDFLAGS)
