OBJ_TP=tp/trace.o tp/sizefn.o tp/types.o tp/emu.o tp/match.o tp/synth.o tp/plugin.o

STATIC_OBJ+=${OBJ_TP}
TARGET_TP=anal_tp.${EXT_SO}

ALL_TARGETS+=${TARGET_TP}

${TARGET_TP}: ${OBJ_TP}
	${CC} $(call libname,anal_tp) ${LDFLAGS} \
		${CFLAGS} -o anal_tp.${EXT_SO} ${OBJ_TP}
