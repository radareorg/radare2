OBJ_TIC=bin_tic.o

STATIC_OBJ+=${OBJ_TIC}
TARGET_TIC=bin_tic.${EXT_SO}

ALL_TARGETS+=${TARGET_TIC}

${TARGET_TIC}: ${OBJ_TIC}
	${CC} $(call libname,bin_tic) -shared ${CFLAGS} \
		-o ${TARGET_TIC} ${OBJ_TIC} $(LINK) $(LDFLAGS)
