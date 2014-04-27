OBJ_MALLOC=io_malloc.o

STATIC_OBJ+=${OBJ_MALLOC}
TARGET_MALLOC=io_malloc.${EXT_SO}
ALL_TARGETS+=${TARGET_MALLOC}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_MALLOC}: ${OBJ_MALLOC}
	${CC_LIB} $(call libname,io_malloc) ${CFLAGS} -o ${TARGET_MALLOC} ${OBJ_MALLOC} ${LINKFLAGS}
