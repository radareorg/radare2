OBJ_WS=anal_ws.o

STATIC_OBJ+=${OBJ_WS}
TARGET_WS=anal_ws.${EXT_SO}

ALL_TARGETS+=${TARGET_WS}
#LDFLAGS+=-L../../lib -lr_lib
#LDFLAGS+=-L../../syscall -lr_syscall
#LDFLAGS+=-L../../diff -lr_diff

${TARGET_WS}: ${OBJ_WS}
	${CC} $(call libname,anal_ws) ${LDFLAGS} ${CFLAGS} -o anal_ws.${EXT_SO} ${OBJ_WS}
