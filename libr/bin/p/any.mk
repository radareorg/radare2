OBJ_ANY=bin_any.o

STATIC_OBJ+=${OBJ_ANY}
TARGET_ANY=bin_any.${EXT_SO}

ALL_TARGETS+=${TARGET_ANY}

${TARGET_ANY}: ${OBJ_ANY}
	${CC} $(call libname,bin_any) ${CFLAGS} $(LDFLAGS) ${OBJ_ANY}
