OBJ_HUNK=bin_hunk.o

STATIC_OBJ+=${OBJ_HUNK}
TARGET_HUNK=bin_hunk.${EXT_SO}

ALL_TARGETS+=${TARGET_HUNK}

${TARGET_HUNK}: ${OBJ_HUNK}
	${CC} $(call libname,bin_hunk) -shared ${CFLAGS} \
		-o ${TARGET_HUNK} ${OBJ_HUNK} $(LINK) $(LDFLAGS)
