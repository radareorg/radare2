OBJ_MACH=io_mach.o

STATIC_OBJ+=${OBJ_MACH}
TARGET_MACH=io_mach.${EXT_SO}
ALL_TARGETS+=${TARGET_MACH}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_MACH}: ${OBJ_MACH}
	${CC_LIB} $(call libname,io_mach) ${CFLAGS} -o ${TARGET_MACH} ${OBJ_MACH} ${LINKFLAGS}
