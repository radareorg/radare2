OBJ_IODBG=io_debug.o

STATIC_OBJ+=${OBJ_IODBG}
TARGET_IODBG=io_debug.${EXT_SO}

ALL_TARGETS+=${TARGET_IODBG}


ifeq (${WITHPIC},0)
LINKFLAGS=../../socket/libr_socket.a
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS=-L../../socket -lr_socket
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

${TARGET_IODBG}: ${OBJ_IODBG}
	${CC} $(call libname,io_debug) ${CFLAGS} ${LDFLAGS_LIB} \
		${LINKFLAGS} ${LDFLAGS_LINKPATH}.. -L.. -lr_io ${OBJ_IODBG}
