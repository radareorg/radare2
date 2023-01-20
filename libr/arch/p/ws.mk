OBJ_WS=p/ws/plugin.o

STATIC_OBJ+=${OBJ_WS}
TARGET_WS=arch_ws.${EXT_SO}

ALL_TARGETS+=${TARGET_WS}

${TARGET_WS}: ${OBJ_WS}
	${CC} $(call libname,arch_ws) ${LDFLAGS} ${CFLAGS} \
		 -o arch_ws.${EXT_SO} ${OBJ_WS}
