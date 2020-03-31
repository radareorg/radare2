OBJ_NE=bin_ne.o ../format/ne/ne.o

STATIC_OBJ+=${OBJ_NE}
TARGET_NE=bin_ne.${EXT_SO}

ALL_TARGETS+=${TARGET_NE}

${TARGET_NE}: ${OBJ_NE}
	-${CC} $(call libname, bin_ne) ${CFLAGS} \
	${OBJ_NE} $(LINK) $(LDFLAGS)
