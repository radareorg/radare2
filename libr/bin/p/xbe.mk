OBJ_XBE=bin_xbe.o

STATIC_OBJ+=${OBJ_XBE}
TARGET_XBE=bin_xbe.${EXT_SO}

ALL_TARGETS+=${TARGET_XBE}

${TARGET_XBE}: ${OBJ_XBE}
	${CC} $(call libname,bin_xbe) -shared ${CFLAGS} \
		-o ${TARGET_XBE} ${OBJ_XBE} $(LINK) ${LDFLAGS}
