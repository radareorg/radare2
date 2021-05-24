OBJ_SOCKET=io_socket.o

STATIC_OBJ+=${OBJ_SOCKET}
TARGET_SOCKET=io_socket.${EXT_SO}
ALL_TARGETS+=${TARGET_SOCKET}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_SOCKET}: ${OBJ_SOCKET}
	${CC_LIB} $(call libname,io_socket) ${CFLAGS} -o ${TARGET_SOCKET} \
		${LDFLAGS} ${OBJ_SOCKET} ${LINKFLAGS}
