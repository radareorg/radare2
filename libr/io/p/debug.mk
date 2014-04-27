OBJ_IODBG=io_debug.o

STATIC_OBJ+=${OBJ_IODBG}
TARGET_IODBG=io_debug.${EXT_SO}

ALL_TARGETS+=${TARGET_IODBG}


ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/libr_socket.a
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS=-L../../socket -lr_socket
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io 
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

${TARGET_IODBG}: ${OBJ_IODBG}
	${CC} $(call libname,io_debug) ${CFLAGS} ${LDFLAGS_LIB} \
		${LINKFLAGS} ${LDFLAGS_LINKPATH}.. ${OBJ_IODBG} -L.. -lr_io
