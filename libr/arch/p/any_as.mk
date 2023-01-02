OBJ_ANYAS=p/any_as/plugin.o

STATIC_OBJ+=${OBJ_ANYAS}
TARGET_ANYAS=arch_as.${EXT_SO}

ALL_TARGETS+=${TARGET_ANYAS}

${TARGET_ANYAS}: ${OBJ_ANYAS}
	${CC} ${CFLAGS} $(call libname,arch_as) $(CS_CFLAGS) \
		-o arch_as.${EXT_SO} ${OBJ_ANYAS} $(CS_LDFLAGS)
