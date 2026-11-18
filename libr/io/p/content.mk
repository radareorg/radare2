OBJ_CONTENT=io_content.o

STATIC_OBJ+=${OBJ_CONTENT}
TARGET_CONTENT=io_content.${EXT_SO}
ALL_TARGETS+=${TARGET_CONTENT}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_CONTENT}: ${OBJ_CONTENT}
	${CC_LIB} $(call libname,io_content) ${CFLAGS} -o ${TARGET_CONTENT} ${OBJ_CONTENT} ${LINKFLAGS}
