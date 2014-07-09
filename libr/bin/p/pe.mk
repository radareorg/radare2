OBJ_PE=bin_pe.o ../format/pe/pe.o

STATIC_OBJ+=${OBJ_PE}
TARGET_PE=bin_pe.${EXT_SO}

ALL_TARGETS+=${TARGET_PE}

${TARGET_PE}: ${OBJ_PE}
	-${CC} $(call libname,bin_pe) ${CFLAGS} \
	$(OBJ_PE) $(LINK) $(LDFLAGS)
