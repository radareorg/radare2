OBJ_FATMACH0=bin_xtr_fatmach0.o ../format/mach0/fatmach0.o

STATIC_OBJ+=${OBJ_FATMACH0}
TARGET_FATMACH0=bin_xtr_fatmach0.${EXT_SO}

ALL_TARGETS+=${TARGET_FATMACH0}

${TARGET_FATMACH0}: ${OBJ_FATMACH0}
	-${CC} $(call libname,bin_xtr_fatmach0) -shared ${CFLAGS} \
		-o ${TARGET_FATMACH0} ${OBJ_FATMACH0} $(LINK) $(LDFLAGS)
