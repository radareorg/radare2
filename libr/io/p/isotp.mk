OBJ_ISOTP=io_isotp.o

STATIC_OBJ+=${OBJ_ISOTP}
TARGET_ISOTP=io_isotp.${EXT_SO}
ALL_TARGETS+=${TARGET_ISOTP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_ISOTP}: ${OBJ_ISOTP}
	${CC_LIB} $(call libname,io_isotp) ${CFLAGS} -o ${TARGET_ISOTP} \
		${LDFLAGS} ${OBJ_ISOTP} ${LINKFLAGS}
