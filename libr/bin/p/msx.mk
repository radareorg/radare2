OBJ_MSX=bin_msx.o

STATIC_OBJ+=${OBJ_MSX}
TARGET_MSX=bin_msx.${EXT_SO}

ALL_TARGETS+=${TARGET_MSX}

${TARGET_MSX}: ${OBJ_MSX}
	${CC} $(call libname,bin_msx) -shared ${CFLAGS} \
		-o ${TARGET_MSX} ${OBJ_MSX} $(LINK) $(LDFLAGS)
