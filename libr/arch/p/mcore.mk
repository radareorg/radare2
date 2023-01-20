OBJ_MCORE=p/mcore/plugin.o p/mcore/mcore.o

STATIC_OBJ+=${OBJ_MCORE}

TARGET_MCORE=arch_mcore.${EXT_SO}

ALL_TARGETS+=${TARGET_MCORE}

${TARGET_MCORE}: ${OBJ_MCORE}
	${CC} ${CFLAGS} $(call libname,arch_mcore) $(CS_LDFLAGS) \
		-o arch_mcore.${EXT_SO} ${OBJ_MCORE}
