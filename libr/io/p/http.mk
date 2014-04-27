OBJ_HTTP=io_http.o

STATIC_OBJ+=${OBJ_HTTP}
TARGET_HTTP=io_http.${EXT_SO}
ALL_TARGETS+=${TARGET_HTTP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
LINKFLAGS+=../../io/libr_socket.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L../../socket -lr_socket
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_HTTP}: ${OBJ_HTTP}
	${CC_LIB} $(call libname,io_http) ${CFLAGS} -o ${TARGET_HTTP} ${OBJ_HTTP} ${LINKFLAGS}
