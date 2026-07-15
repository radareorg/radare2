OBJ_MACHO=bin_macho.o ../format/macho/macho.o
OBJ_MACHO+=../format/objc/macho_classes.o ../format/objc/macho64_classes.o
OBJ_MACHO+=bin_write_macho.o

STATIC_OBJ+=${OBJ_MACHO}
TARGET_MACHO=bin_macho.${EXT_SO}

ALL_TARGETS+=${TARGET_MACHO}

${TARGET_MACHO}: ${OBJ_MACHO}
	-${CC} $(call libname,bin_macho) ${CFLAGS} \
		${OBJ_MACHO} ${SHLR}/../subprojects/sdb/src/libsdb.a \
		$(LINK) $(LDFLAGS)
