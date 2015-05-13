OBJ_R2PIPE=io_r2pipe.o

STATIC_OBJ+=${OBJ_R2PIPE}
TARGET_R2PIPE=io_r2pipe.${EXT_SO}
ALL_TARGETS+=${TARGET_R2PIPE}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
LINKFLAGS+=../../io/libr_socket.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L../../socket -lr_socket
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_R2PIPE}: ${OBJ_R2PIPE}
	${CC_LIB} $(call libname,io_r2pipe) ${CFLAGS} \
		-o ${TARGET_R2PIPE} ${OBJ_R2PIPE} ${LINKFLAGS}
