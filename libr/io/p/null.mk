OBJ_NULL=io_null.o

STATIC_OBJ+=${OBJ_NULL}
TARGET_NULL=io_null.${EXT_SO}
ALL_TARGETS+=${TARGET_NULL}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_NULL}: ${OBJ_NULL}
	${CC_LIB} $(call libname,io_null) ${CFLAGS} -o ${TARGET_NULL} \
		${LDFLAGS} ${OBJ_NULL} ${LINKFLAGS}
