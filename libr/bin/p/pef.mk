OBJ_PEF=bin_pef.o

STATIC_OBJ+=${OBJ_PEF}
TARGET_PEF=bin_pef.${EXT_SO}

ALL_TARGETS+=${TARGET_PEF}

${TARGET_PEF}: ${OBJ_PEF}
	${CC} $(call libname,bin_pef) -shared ${CFLAGS} \
		-o ${TARGET_PEF} ${OBJ_PEF} $(LINK) $(LDFLAGS)
