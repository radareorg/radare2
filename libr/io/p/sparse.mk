OBJ_SPARSE=io_sparse.o

STATIC_OBJ+=${OBJ_SPARSE}
TARGET_SPARSE=io_sparse.${EXT_SO}
ALL_TARGETS+=${TARGET_SPARSE}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_SPARSE}: ${OBJ_SPARSE}
	${CC_LIB} $(call libname,io_sparse) ${CFLAGS} -o ${TARGET_SPARSE} \
		${LDFLAGS} ${OBJ_SPARSE} ${LINKFLAGS}
