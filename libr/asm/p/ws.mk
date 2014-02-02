OBJ_WS=asm_ws.o

STATIC_OBJ+=${OBJ_WS}
TARGET_WS=asm_ws.${EXT_SO}

ALL_TARGETS+=${TARGET_WS}

${TARGET_WS}: ${OBJ_WS}
	${CC} ${call libname,asm_ws} ${CFLAGS} -o ${TARGET_WS} ${OBJ_WS}
