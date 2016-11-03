OBJ_MENUET=bin_menuet.o

STATIC_OBJ+=${OBJ_MENUET}
TARGET_MENUET=bin_menuet.${EXT_SO}

ALL_TARGETS+=${TARGET_MENUET}

${TARGET_MENUET}: ${OBJ_MENUET}
	-${CC} $(call libname,bin_menuet) ${CFLAGS} ${OBJ_MENUET}
