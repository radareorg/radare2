OBJ_WS=anal_ws.o

STATIC_OBJ+=${OBJ_WS}
TARGET_WS=anal_ws.${EXT_SO}

ALL_TARGETS+=${TARGET_WS}

${TARGET_WS}: ${OBJ_WS}
	${CC} $(call libname,anal_ws) ${LDFLAGS} ${CFLAGS} \
		 -o anal_ws.${EXT_SO} ${OBJ_WS}
