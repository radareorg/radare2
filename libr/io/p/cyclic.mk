OBJ_CYCLIC=io_cyclic.o

STATIC_OBJ+=${OBJ_CYCLIC}
TARGET_CYCLIC=io_cyclic.${EXT_SO}
ALL_TARGETS+=${TARGET_CYCLIC}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_CYCLIC}: ${OBJ_CYCLIC}
	${CC_LIB} $(call libname,io_cyclic) ${CFLAGS} -o ${TARGET_CYCLIC} \
		${LDFLAGS} ${OBJ_CYCLIC} ${LINKFLAGS}
