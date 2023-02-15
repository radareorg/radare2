OBJ_XTAC=bin_xtac.o

STATIC_OBJ+=${OBJ_XTAC}
TARGET_XTAC=bin_xtac.${EXT_SO}

ALL_TARGETS+=${TARGET_XTAC}

${TARGET_XTAC}: ${OBJ_XTAC}
	${CC} $(call libname,bin_xtac) -shared ${CFLAGS} \
		-o ${TARGET_XTAC} ${OBJ_XTAC} ${LINK} ${LDFLAGS}
