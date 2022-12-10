OBJ_SERIAL=io_serial.o

STATIC_OBJ+=${OBJ_SERIAL}
TARGET_SERIAL=io_serial.${EXT_SO}
ALL_TARGETS+=${TARGET_SERIAL}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_SERIAL}: ${OBJ_SERIAL}
	${CC_LIB} $(call libname,io_serial) ${CFLAGS} -o ${TARGET_SERIAL} \
		${LDFLAGS} ${OBJ_SERIAL} ${LINKFLAGS}
