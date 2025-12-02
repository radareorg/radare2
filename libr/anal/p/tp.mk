OBJ_TP=anal_tp.o

STATIC_OBJ+=${OBJ_TP}
TARGET_TP=anal_tp.${EXT_SO}

ALL_TARGETS+=${TARGET_TP}

${TARGET_TP}: ${OBJ_TP}
	${CC} $(call libname,anal_tp) ${LDFLAGS} \
		${CFLAGS} -o anal_tp.${EXT_SO} ${OBJ_TP}
