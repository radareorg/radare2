OBJ_PRJ=bin_prj.o

STATIC_OBJ+=${OBJ_PRJ}
TARGET_PRJ=bin_prj.${EXT_SO}

ALL_TARGETS+=${TARGET_PRJ}

${TARGET_PRJ}: ${OBJ_PRJ}
	${CC} $(call libname,bin_prj) -shared ${CFLAGS} \
		-o ${TARGET_PRJ} ${OBJ_PRJ} $(LINK) $(LDFLAGS)
