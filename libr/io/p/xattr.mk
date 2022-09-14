OBJ_XATTR=io_xattr.o

STATIC_OBJ+=${OBJ_XATTR}
TARGET_XATTR=io_xattr.${EXT_SO}
ALL_TARGETS+=${TARGET_XATTR}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_XATTR}: ${OBJ_XATTR}
	${CC_LIB} $(call libname,io_xattr) ${CFLAGS} -o ${TARGET_XATTR} \
		${LDFLAGS} ${OBJ_XATTR} ${LINKFLAGS}
