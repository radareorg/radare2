OBJ_RBUF=io_rbuf.o

STATIC_OBJ+=${OBJ_RBUF}
TARGET_RBUF=io_rbuf.${EXT_SO}
ALL_TARGETS+=${TARGET_RBUF}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_RBUF}: ${OBJ_RBUF}
	${CC_LIB} $(call libname,io_rbuf) ${CFLAGS} -o ${TARGET_RBUF} \
		${LDFLAGS} ${OBJ_RBUF} ${LINKFLAGS}
