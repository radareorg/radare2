OBJ_IHEX=io_ihex.o

STATIC_OBJ+=${OBJ_IHEX}
TARGET_IHEX=io_ihex.${EXT_SO}
ALL_TARGETS+=${TARGET_IHEX}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_IHEX}: ${OBJ_IHEX}
	${CC_LIB} $(call libname,io_hex) ${CFLAGS} -o ${TARGET_IHEX} ${OBJ_IHEX} ${LINKFLAGS}
