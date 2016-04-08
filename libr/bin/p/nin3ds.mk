OBJ_NIN3DS=bin_nin3ds.o

STATIC_OBJ+=${OBJ_NIN3DS}
TARGET_NIN3DS=bin_nin3ds.${EXT_SO}

ALL_TARGETS+=${TARGET_NIN3DS}

${TARGET_NIN3DS}: ${OBJ_NIN3DS}
	${CC} $(call libname,bin_nin3ds) ${CFLAGS} $(OBJ_NIN3DS) $(LINK) $(LDFLAGS) \
	-L../../magic -lr_magic
