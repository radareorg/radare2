OBJ_SFC=bin_sfc.o

STATIC_OBJ+=${OBJ_SFC}
TARGET_SFC=bin_sfc.${EXT_SO}

ALL_TARGETS+=${TARGET_SFC}

${TARGET_SFC}: ${OBJ_SFC}
	${CC} $(call libname,bin_sfc) -shared ${CFLAGS} \
		-o ${TARGET_SFC} ${OBJ_SFC} $(LINK) $(LDFLAGS)
