OBJ_TCP=io_tcp.o

STATIC_OBJ+=${OBJ_TCP}
TARGET_TCP=io_tcp.${EXT_SO}
ALL_TARGETS+=${TARGET_TCP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
LINKFLAGS+=../../io/libr_socket.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L../../socket -lr_socket
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_TCP}: ${OBJ_TCP}
	${CC_LIB} $(call libname,io_tcp) ${CFLAGS} -o ${TARGET_TCP} ${OBJ_TCP} ${LINKFLAGS}
