OBJ_TCPSLURP=io_tcpslurp.o

STATIC_OBJ+=${OBJ_TCPSLURP}
TARGET_TCPSLURP=io_tcpslurp.${EXT_SO}
ALL_TARGETS+=${TARGET_TCPSLURP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
LINKFLAGS+=../../io/libr_socket.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L../../socket -lr_socket
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_TCPSLURP}: ${OBJ_TCPSLURP}
	${CC_LIB} $(call libname,io_tcpslurp) ${CFLAGS} -o ${TARGET_TCPSLURP} ${OBJ_TCPSLURP} ${LINKFLAGS}
