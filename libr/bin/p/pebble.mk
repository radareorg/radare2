OBJ_PEBBLE=bin_pebble.o

STATIC_OBJ+=${OBJ_PEBBLE}
TARGET_PEBBLE=bin_pebble.${EXT_SO}

ALL_TARGETS+=${TARGET_PEBBLE}

${TARGET_PEBBLE}: ${OBJ_PEBBLE}
	-${CC} $(call libname,bin_pebble) ${CFLAGS} \
		$(OBJ_PEBBLE) $(LINK) $(LDFLAGS)
