OBJ_PE64=bin_pe64.o bin_write_pe64.o ../format/pe/pe64.o ../format/pe/pe64_write.o

STATIC_OBJ+=${OBJ_PE64}
TARGET_PE64=bin_pe64.${EXT_SO}

ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_PE64}

${TARGET_PE64}: ${OBJ_PE64}
	-${CC} $(call libname,bin_pe64) ${CFLAGS} \
		$(OBJ_PE64) $(LINK) $(LDFLAGS)
endif
