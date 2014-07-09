OBJ_BIOS=bin_bios.o

STATIC_OBJ+=${OBJ_BIOS}
TARGET_BIOS=bin_bios.${EXT_SO}

ALL_TARGETS+=${TARGET_BIOS}

${TARGET_BIOS}: ${OBJ_BIOS}
	${CC} $(call libname,bin_bios) -shared ${CFLAGS} \
		-o ${TARGET_BIOS} ${OBJ_BIOS} $(LINK) $(LDFLAGS)
