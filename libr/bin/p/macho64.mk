OBJ_MACHO64=bin_macho64.o
OBJ_MACHO64+=bin_write_macho64.o
OBJ_MACHO64+=../format/macho/macho64.o

STATIC_OBJ+=${OBJ_MACHO64}
TARGET_MACHO64=bin_macho64.${EXT_SO}

ALL_TARGETS+=${TARGET_MACHO64}

${TARGET_MACHO64}: ${OBJ_MACHO64}
	-${CC} $(call libname,bin_macho64) \
		-shared ${CFLAGS} -o ${TARGET_MACHO64} \
		${OBJ_MACHO64} $(LINK) $(LDFLAGS)
