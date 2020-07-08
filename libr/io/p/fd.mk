OBJ_FD=io_fd.o

STATIC_OBJ+=${OBJ_FD}
TARGET_FD=io_fd.${EXT_SO}
ALL_TARGETS+=${TARGET_FD}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_FD}: ${OBJ_FD}
	${CC_LIB} $(call libname,io_fd) ${CFLAGS} -o ${TARGET_FD} ${OBJ_FD} ${LINKFLAGS}
