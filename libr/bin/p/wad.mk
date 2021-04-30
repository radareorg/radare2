OBJ_WAD=bin_wad.o

STATIC_OBJ+=${OBJ_WAD}
TARGET_WAD=bin_wad.${EXT_SO}

ALL_TARGETS+=${TARGET_WAD}

${TARGET_WAD}: ${OBJ_WAD}
	${CC} $(call libname,bin_wad) -shared ${CFLAGS} \
		-o ${TARGET_WAD} ${OBJ_WAD} $(LINK) $(LDFLAGS)
