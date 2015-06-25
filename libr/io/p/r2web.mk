OBJ_R2WEB=io_r2web.o

STATIC_OBJ+=${OBJ_R2WEB}
TARGET_R2WEB=io_r2web.${EXT_SO}
ALL_TARGETS+=${TARGET_R2WEB}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
LINKFLAGS+=../../io/libr_socket.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L../../socket -lr_socket
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_R2WEB}: ${OBJ_R2WEB}
	${CC_LIB} $(call libname,io_r2web) ${CFLAGS} -o ${TARGET_R2WEB} ${OBJ_R2WEB} ${LINKFLAGS}
