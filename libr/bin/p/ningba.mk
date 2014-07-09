OBJ_NINGBA=bin_ningba.o

STATIC_OBJ+=${OBJ_NINGBA}
TARGET_NINGBA=bin_ningba.${EXT_SO}

ALL_TARGETS+=${TARGET_NINGBA}

${TARGET_NINGBA}: ${OBJ_NINGBA}
	${CC} $(call libname,bin_ningba) -shared ${CFLAGS} \
		-o ${TARGET_NINGBA} ${OBJ_NINGBA} $(LINK) $(LDFLAGS)
