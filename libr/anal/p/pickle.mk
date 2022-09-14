OBJ_PYPICK=anal_pickle.o

STATIC_OBJ+=$(OBJ_PYPICK)
TARGET_PYPICK=anal_pickle.${EXT_SO}

ALL_TARGETS+=${TARGET_PYPICK}

${TARGET_PYPICK}: ${OBJ_PYPICK}
	${CC} ${CFLAGS} $(call libname,anal_pickle) $(CS_CFLAGS) \
		-o anal_pickle.${EXT_SO} ${OBJ_PYPICK} $(CS_LDFLAGS)
