OBJ_DEFAULT=io_default.o

STATIC_OBJ+=${OBJ_DEFAULT}
TARGET_DEFAULT=io_default.${EXT_SO}
ALL_TARGETS+=${TARGET_DEFAULT}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_DEFAULT}: ${OBJ_DEFAULT}
	${CC_LIB} $(call libname,io_default) ${CFLAGS} -o ${TARGET_DEFAULT} ${OBJ_DEFAULT} ${LINKFLAGS}
