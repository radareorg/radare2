OBJ_PE=bin_pe.o bin_write_pe.o ../format/pe/pe.o ../format/pe/pe_write.o
OBJ_PE+=../format/pe/dotnet.o

STATIC_OBJ+=${OBJ_PE}
TARGET_PE=bin_pe.${EXT_SO}

ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_PE}

${TARGET_PE}: ${OBJ_PE}
	-${CC} $(call libname,bin_pe) ${CFLAGS} \
	$(OBJ_PE) $(LINK) $(LDFLAGS)
endif
