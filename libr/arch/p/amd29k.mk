OBJ_AMD29K=p/amd29k/plugin.o

STATIC_OBJ+=${OBJ_AMD29K}
TARGET_AMD29K=arch_amd29k.${EXT_SO}

ALL_TARGETS+=${TARGET_AMD29K}

${TARGET_AMD29K}: ${OBJ_AMD29K}
	${CC} ${CFLAGS} $(call libname,arch_amd29k) $(CS_CFLAGS) \
		-o arch_amd29k.${EXT_SO} ${OBJ_AMD29K} $(CS_LDFLAGS)
