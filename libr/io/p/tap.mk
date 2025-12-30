OBJ_TAP=io_tap.o

STATIC_OBJ+=${OBJ_TAP}
TARGET_TAP=io_tap.${EXT_SO}
ALL_TARGETS+=${TARGET_TAP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_TAP}: ${OBJ_TAP}
	${CC_LIB} $(call libname,io_tap) ${CFLAGS} -o ${TARGET_TAP} ${OBJ_TAP} ${LINKFLAGS}
