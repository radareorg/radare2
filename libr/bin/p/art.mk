OBJ_ART=bin_art.o

STATIC_OBJ+=${OBJ_ART}
TARGET_ART=bin_art.${EXT_SO}

ALL_TARGETS+=${TARGET_ART}

${TARGET_ART}: ${OBJ_ART}
	${CC} $(call libname,bin_art) -shared ${CFLAGS} \
		-o ${TARGET_ART} ${OBJ_ART} $(LINK) $(LDFLAGS)
