OBJ_PYPICK=p/pickle/plugin.o

STATIC_OBJ+=$(OBJ_PYPICK)
TARGET_PYPICK=arch_pickle.${EXT_SO}

ALL_TARGETS+=${TARGET_PYPICK}

${TARGET_PYPICK}: ${OBJ_PYPICK}
	${CC} ${CFLAGS} $(call libname,arch_pickle) $(CS_CFLAGS) \
		-o arch_pickle.${EXT_SO} ${OBJ_PYPICK} $(CS_LDFLAGS)
