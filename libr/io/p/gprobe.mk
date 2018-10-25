OBJ_GPROBE=io_gprobe.o

STATIC_OBJ+=${OBJ_GPROBE}
TARGET_GPROBE=io_gprobe.${EXT_SO}
ALL_TARGETS+=${TARGET_GPROBE}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_GPROBE}: ${OBJ_GPROBE}
	${CC_LIB} $(call libname,io_gprobe) ${CFLAGS} -o ${TARGET_GPROBE} ${OBJ_GPROBE} ${LINKFLAGS}
