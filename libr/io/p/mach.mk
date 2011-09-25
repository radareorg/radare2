OBJ_MACH=io_mach.o

STATIC_OBJ+=${OBJ_MACH}
TARGET_MACH=io_mach.${EXT_SO}
ALL_TARGETS+=${TARGET_MACH}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif

${TARGET_MACH}: ${OBJ_MACH}
	${CC_LIB} $(call libname,io_mach) ${CFLAGS} -o ${TARGET_MACH} ${OBJ_MACH} ${LINKFLAGS}
