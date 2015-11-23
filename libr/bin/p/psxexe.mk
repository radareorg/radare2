OBJ_PSXEXE=bin_psxexe.o

STATIC_OBJ+=${OBJ_PSXEXE}
TARGET_PSXEXE=bin_psxexe.${EXT_SO}

ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_PSXEXE}

${TARGET_PSXEXE}: ${OBJ_PSXEXE}
	-${CC} $(call libname,bin_psxexe) ${CFLAGS} \
	$(OBJ_PSXEXE) $(LINK) $(LDFLAGS)
endif
