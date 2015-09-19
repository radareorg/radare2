OBJ_NES=bin_nes.o

STATIC_OBJ+=${OBJ_NES}
TARGET_NES=bin_nes.${EXT_SO}

ALL_TARGETS+=${TARGET_NES}

${TARGET_NES}: ${OBJ_NES}
	${CC} $(call libname,bin_nes) -shared ${CFLAGS} \
		-o ${TARGET_NES} ${OBJ_NES} $(LINK) $(LDFLAGS)
