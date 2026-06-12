OBJ_NAME=bin_ftab
OBJ_FTAB=bin_ftab.o

STATIC_OBJ+=${OBJ_FTAB}
TARGET_FTAB=bin_ftab.${EXT_SO}

ALL_TARGETS+=${TARGET_FTAB}

${TARGET_FTAB}: ${OBJ_FTAB}
	${CC} $(call libname,bin_ftab) -shared ${CFLAGS} \
		-o ${TARGET_FTAB} ${OBJ_FTAB} $(LINK) $(LDFLAGS)
