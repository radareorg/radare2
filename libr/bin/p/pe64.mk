OBJ_PE64=bin_pe64.o ../format/pe/pe64.o

STATIC_OBJ+=${OBJ_PE64}
TARGET_PE64=bin_pe64.${EXT_SO}

ALL_TARGETS+=${TARGET_PE64}

${TARGET_PE64}: ${OBJ_PE64}
	-${CC} $(call libname,bin_pe64) ${CFLAGS} \
		$(OBJ_PE64) $(LINK) $(LDFLAGS)
