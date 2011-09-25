OBJ_HARET=io_haret.o

STATIC_OBJ+=${OBJ_HARET}
TARGET_HARET=io_haret.${EXT_SO}
ALL_TARGETS+=${TARGET_HARET}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../socket/libr_socket.a
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../socket -lr_socket
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LINKFLAGS+=${SSL_LDFLAGS}
endif

${TARGET_HARET}: ${OBJ_HARET}
	${CC_LIB} ${TARGET_HARET} $(call libname,io_haret) ${CFLAGS} ${OBJ_HARET} ${LINKFLAGS}
