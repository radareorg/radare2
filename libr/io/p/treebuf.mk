OBJ_TREEBUF=io_treebuf.o

STATIC_OBJ+=${OBJ_TREEBUF}
TARGET_TREEBUF=io_treebuf.${EXT_SO}
ALL_TARGETS+=${TARGET_TREEBUF}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_TREEBUF}: ${OBJ_TREEBUF}
	${CC_LIB} $(call libname,io_treebuf) ${CFLAGS} -o ${TARGET_TREEBUF} ${OBJ_TREEBUF} ${LINKFLAGS}
