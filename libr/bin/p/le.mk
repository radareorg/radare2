OBJ_le=bin_le.o ../format/le/le.o

STATIC_OBJ+=${OBJ_le}
TARGET_le=bin_le.${EXT_SO}

ALL_TARGETS+=${TARGET_le}

${TARGET_le}: ${OBJ_le}
	-${CC} $(call libname, bin_le) ${CFLAGS} \
	${OBJ_le} $(LINK) $(LDFLAGS)
