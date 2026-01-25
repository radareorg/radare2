OBJ_SREC=io_srec.o

STATIC_OBJ+=${OBJ_SREC}
TARGET_SREC=io_srec.${EXT_SO}
ALL_TARGETS+=${TARGET_SREC}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_SREC}: ${OBJ_SREC}
	${CC_LIB} $(call libname,io_srec) ${CFLAGS} -o ${TARGET_SREC} ${OBJ_SREC} ${LINKFLAGS}
