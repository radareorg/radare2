OBJ_IO=bin_io.o

STATIC_OBJ+=${OBJ_IO}
TARGET_IO=bin_io.${EXT_SO}

ALL_TARGETS+=${TARGET_IO}

${TARGET_IO}: ${OBJ_IO}
	${CC} $(call libname,bin_io) -shared ${CFLAGS} \
		-o ${TARGET_IO} ${OBJ_IO} $(LINK) $(LDFLAGS)
